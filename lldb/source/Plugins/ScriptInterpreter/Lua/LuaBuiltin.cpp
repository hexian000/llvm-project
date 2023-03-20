#include "Lua.h"

namespace lldb_private {

const char Lua::m_builtin[] = u8R"Lua(
local function prepare()
    lldb.debugger = lldb.SBDebugger.FindDebuggerWithID(1)
    lldb.target = lldb.debugger:GetSelectedTarget()
    lldb.process = lldb.target:GetProcess()
    lldb.thread = lldb.process:GetSelectedThread()
    lldb.frame = lldb.thread:GetSelectedFrame()
end

local function printf(s, ...)
    print(string.format(s, ...))
end

local function cmdf(s, ...)
    local cmd = string.format(s, ...)
    local ret = lldb.SBCommandReturnObject()
    local interpreter = lldb.debugger:GetCommandInterpreter()
    interpreter:HandleCommand(cmd, ret)
    if not ret:Succeeded() then
        lldb.debugger:GetErrorFile():Flush()
        local err = string.gsub(ret:GetError(), "\n$", "")
        error(err)
    end
    lldb.debugger:GetOutputFile():Flush()
    local out = string.gsub(ret:GetOutput(), "\n$", "")
    return out
end

local function evalf(ctx, s, ...)
    local expr = string.format(s, ...)
    local value = ctx:EvaluateExpression(expr)
    if not value:IsValid() then
        error("failed evaluating: " .. expr)
    end
    return value:GetValue()
end

local function read_string(ctx, expr, len)
    local value = ctx:EvaluateExpression(expr)
    local err = lldb.SBError()
    local process = value:GetProcess()
    local buf = process:ReadCStringFromMemory(tonumber(value:GetValue()), len + 1, err)
    if not err:Success() then
        error(err:GetCString())
    end
    -- printf("read_string: [%d] %q", len, buf)
    return buf
end

unreal = {}

function unreal.pname(index)
    pcall(prepare)
    local ctx = lldb.target
    local shift = tonumber(evalf(ctx, "FNameDebugVisualizer::OffsetBits"))
    local mask = tonumber(evalf(ctx, "FNameDebugVisualizer::OffsetMask"))
    local stride = tonumber(evalf(ctx, "FNameDebugVisualizer::EntryStride"))
    local i = index >> shift
    local j = (index & mask) * stride
    local entry = evalf(ctx, "&GNameBlocksDebug[%d][%d]", i, j)
    -- printf("entry = %q", entry)
    local len = tonumber(evalf(ctx, "((FNameEntry*)%s)->Header.Len", entry))
    -- printf("len = %d", len)
    local name = read_string(ctx, string.format("&((FNameEntry*)%s)->AnsiName", entry), len)
    printf("FName(%d) = %q", index, name)
end

function unreal.pweak(index)
    pcall(prepare)
    local chunk = 65536
    local i = index // chunk
    local j = index % chunk
    print(cmdf("print GUObjectArray.ObjObjects.Objects[%d][%d]", i, j))
end

function unreal.ptype(ptr)
    pcall(prepare)
    local vtable = tonumber(evalf(lldb.target, string.format("*(void**)0x%x", ptr)))
    printf("vtable: 0x%x", vtable)
    print(cmdf("target modules lookup -a 0x%x", vtable))
end

function unreal.vtable(vtable)
    pcall(prepare)
    local size = tonumber(evalf(lldb.target, "sizeof(void*)"))
    for i = 0, 999 do
        local vfunc = vtable + (i * size)
        local line = cmdf("memory read -c 1 -f A 0x%x", vfunc)
        local ptr = select(3, string.find(line, "^%s*%w+:%s+(%w+)"))
        if tonumber(ptr) == 0 then
            break
        end
        print(line)
    end
end

)Lua";

} // namespace lldb_private
