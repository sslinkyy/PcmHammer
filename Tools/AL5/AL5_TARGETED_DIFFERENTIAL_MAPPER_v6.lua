-- AL5 targeted differential mapper v6: OFFLINE ONLY, NO VEHICLE I/O, NO TUNE SAVE.
-- Derived from the working v5.1 mapper; one cell is edited and restored per case.
-- Descriptor 0 is read-only. Secondary descriptors must be distinct and positive.
-- Reports are mapping evidence, NOT checksum-finalized or flash-ready calibrations.
-- See Docs/AL5/TunerPro/TARGETED_MAPPER.md before running in EFILive V8 F9:Scripting.
local GUI_FD = 0
local EXPECTED_STREAM = "AL5"
local EXPECTED_OS = 15184109
local EXPECTED_TRANS = 15183960
local CAL_START = 0x08000
local CAL_CAPTURE_END = 0x15FFF
local WINDOW_SIZE = 0x1000
local EXPECTED_CAPTURE_BYTES = CAL_CAPTURE_END - CAL_START + 1
local FALLBACK_DIRECTORY = nil

local required = {
    "_efiGetFileProp", "_efiGetPartNumber", "_efiOpenFile", "_efiCloseFile",
    "_efiGetCalId", "_efiGetCalProp", "_efiGetCalValue", "_efiSetCalValue",
}
for _,name in ipairs(required) do
    if type(_G[name]) ~= "function" then
        error("Missing EFILive function " .. name .. ". Run inside EFILive V8 F9:Scripting.")
    end
end

local NULL, ARRAY = {}, {}
local function arr(t) return setmetatable(t or {}, ARRAY) end
local function nullable(v) if v == nil then return NULL end return v end

local function esc(v)
    return '"' .. tostring(v):gsub('[%z\1-\31\\"]', function(c)
        if c == '"' then return '\\"' end
        if c == '\\' then return '\\\\' end
        return string.format('\\u%04x', string.byte(c))
    end) .. '"'
end

local function json(v)
    if v == NULL or v == nil then return "null" end
    local t = type(v)
    if t == "boolean" then return v and "true" or "false" end
    if t == "string" then return esc(v) end
    if t == "number" then
        assert(v == v and v ~= math.huge and v ~= -math.huge, "non-finite JSON number")
        return (string.format("%.17g",v):gsub(",","."))
    end
    assert(t == "table", "unsupported JSON type")
    local p = {}
    if getmetatable(v) == ARRAY then
        for i=1,#v do p[#p+1]=json(v[i]) end
        return "[" .. table.concat(p,",") .. "]"
    end
    local keys={}
    for k in pairs(v) do
        assert(type(k)=="string")
        keys[#keys+1]=k
    end
    table.sort(keys)
    for _,k in ipairs(keys) do p[#p+1]=esc(k)..":"..json(v[k]) end
    return "{" .. table.concat(p,",") .. "}"
end

local function q(fn,...)
    local ok,a,b,c,d = pcall(fn,...)
    if not ok then return nil,tostring(a) end
    if a == nil then
        return nil,"API returned nil; "..tostring(EFI_ErrNum or "").." "..tostring(EFI_ErrMsg or "")
    end
    return a,nil,b,c,d
end

local function near(a,b,tol)
    a,b=tonumber(a),tonumber(b)
    tol=tol or 1e-6
    return a~=nil and b~=nil and math.abs(a-b)<=tol
end

local function verify_identity(fd,label)
    local os=q(_efiGetFileProp,fd,31)
    local stream=q(_efiGetFileProp,fd,62)
    local privacy=q(_efiGetFileProp,fd,81)
    if tonumber(os)~=EXPECTED_OS then error(label..": wrong OS "..tostring(os)) end
    if tostring(stream)~=EXPECTED_STREAM then error(label..": wrong stream "..tostring(stream)) end
    if tonumber(privacy)==2 then error(label..": source is no-view") end

    local count=tonumber(q(_efiGetFileProp,fd,33))
    if not count then error(label..": segment count unavailable") end
    local found=false
    for i=0,count-1 do
        local pn=q(_efiGetPartNumber,fd,i)
        if tonumber(pn)==EXPECTED_TRANS then found=true end
    end
    if not found then error(label..": transmission segment "..EXPECTED_TRANS.." not found") end
end

local function get_cal(fd,id)
    local h,e=q(_efiGetCalId,fd,id)
    if h==nil then error("Cannot resolve "..id..": "..tostring(e)) end
    return h
end

local function get_value(fd,id,c,r)
    local h=get_cal(fd,id)
    local v,e=q(_efiGetCalValue,h,c or 0,r or 0)
    if v==nil then error(id.." read failed: "..tostring(e)) end
    return v
end

-- Positive stock controls verify the GUI-open source is the same baseline used
-- for the successful raw mapping. These are intentionally limited but decisive.
local function verify_baseline(fd)
    local checks = {
        {"D5000",0,0,16.0,0.000001},
        {"D5120",0,0,14.0,0.000001},
        {"D5130",0,0,105.0,0.000001},
        {"D5080",0,0,650.390958,0.001},
        {"D5084",0,0,400.39083,0.001},
        {"D5088",0,0,500.000256,0.001},
        {"D5194",0,0,89.0,0.000001},
        {"D5195",0,0,12.0,0.000001},
        {"D5196",8,9,723.0,0.000001}, -- col 8 / row 9 from verified table
    }
    for _,x in ipairs(checks) do
        local v=get_value(fd,x[1],x[2],x[3])
        if not near(v,x[4],x[5]) then
            error(string.format(
                "Baseline mismatch %s c=%d r=%d expected %.9f got %s. Open the SAME Test-1 stock-equivalent tune.",
                x[1],x[2],x[3],x[4],tostring(v)))
        end
    end
end

-- Raw-view resolver. The previous successful AL5 raw dump used AL5RAW.* views.
-- Try the practical identifier spellings so this script does not depend on
-- whether addresses below 0x10000 were formatted with 4 or 5 hex digits.
local function candidate_raw_names(addr)
    local a4=string.format("%04X",addr)
    local a5=string.format("%05X",addr)
    local ax=string.format("%X",addr)
    local names=arr()
    local seen={}
    local function add(s)
        if not seen[s] then seen[s]=true; names[#names+1]=s end
    end
    add("AL5RAW.RAW_"..a4)
    add("AL5RAW.RAW_"..a5)
    add("AL5RAW.RAW_"..ax)
    add("RAW_"..a4)
    add("RAW_"..a5)
    add("RAW_"..ax)
    return names
end

local function resolve_raw_handle(fd,addr,preferred)
    if preferred then
        local h=q(_efiGetCalId,fd,preferred)
        if h~=nil then return h,preferred end
    end
    for _,name in ipairs(candidate_raw_names(addr)) do
        local h=q(_efiGetCalId,fd,name)
        if h~=nil then return h,name end
    end
    return nil,nil
end

local function u32_to_bytes(v)
    v=tonumber(v)
    if v==nil or v<0 or v>4294967295 or v~=math.floor(v) then
        return nil,"not uint32: "..tostring(v)
    end
    return string.char(
        math.floor(v/16777216)%256,
        math.floor(v/65536)%256,
        math.floor(v/256)%256,
        v%256
    )
end

local function read_raw_view(fd,addr,preferred)
    local h,name=resolve_raw_handle(fd,addr,preferred)
    if h==nil then return nil,nil,"raw view unavailable at $"..string.format("%05X",addr) end

    local cols=tonumber(q(_efiGetCalProp,h,30))
    local rows=tonumber(q(_efiGetCalProp,h,31))
    if not cols or not rows or cols<1 or rows<1 then
        return nil,name,"invalid raw-view dimensions"
    end

    local parts={}
    for r=0,rows-1 do
        for c=0,cols-1 do
            local v,e=q(_efiGetCalValue,h,c,r)
            if v==nil then return nil,name,"raw cell read failed: "..tostring(e) end
            local s,se=u32_to_bytes(v)
            if not s then return nil,name,se end
            parts[#parts+1]=s
        end
    end
    local bytes=table.concat(parts)
    if #bytes~=WINDOW_SIZE then
        return nil,name,string.format(
            "raw view %s returned %d bytes; expected %d",name,#bytes,WINDOW_SIZE)
    end
    return bytes,name,nil
end

local function capture_raw_range(fd,resolved_names)
    local chunks={}
    local names=arr()
    for addr=CAL_START,CAL_CAPTURE_END,WINDOW_SIZE do
        local preferred=resolved_names and resolved_names[addr] or nil
        local bytes,name,e=read_raw_view(fd,addr,preferred)
        if not bytes then
            return nil,nil,string.format("raw capture failed at $%05X: %s",addr,tostring(e))
        end
        chunks[#chunks+1]=bytes
        names[#names+1]={address=addr,name=name}
    end
    local all=table.concat(chunks)
    if #all~=EXPECTED_CAPTURE_BYTES then
        return nil,nil,"raw capture length mismatch: "..tostring(#all)
    end
    return all,names,nil
end

local function names_to_map(list)
    local m={}
    for _,x in ipairs(list) do m[x.address]=x.name end
    return m
end

local function byte_at(raw,address)
    local i=address-CAL_START+1
    if i<1 or i>#raw then return nil end
    return string.byte(raw,i)
end

local function bytes_hex(raw,address,count)
    local i=address-CAL_START+1
    if i<1 or i+count-1>#raw then return nil end
    local p={}
    for j=0,count-1 do p[#p+1]=string.format("%02X",string.byte(raw,i+j)) end
    return table.concat(p)
end

local function set_cell(fd,manifest,id,c,r,target,label)
    local h=get_cal(fd,id)
    local before,e=q(_efiGetCalValue,h,c,r)
    if before==nil then error(id.." marker before-read failed: "..tostring(e)) end

    local rc,se=q(_efiSetCalValue,h,c,r,target)
    if rc==nil then
        error(string.format("%s marker set failed c=%d r=%d target=%s: %s",
            id,c,r,tostring(target),tostring(se)))
    end

    local after,ae=q(_efiGetCalValue,h,c,r)
    if after==nil then error(id.." marker readback failed: "..tostring(ae)) end

    manifest[#manifest+1]={
        id=id,column=c,row=r,label=label,
        before=before,requested=target,readback=after
    }
    return before,after
end

local function make_diff_ranges(a,b)
    local changed=arr()
    for i=1,#a do
        local x,y=string.byte(a,i),string.byte(b,i)
        if x~=y then
            changed[#changed+1]={
                address=CAL_START+i-1,before=x,after=y
            }
        end
    end

    -- Group changes separated by at most 4 unchanged bytes. This keeps related
    -- 16-bit/table edits together without swallowing large untouched regions.
    local ranges=arr()
    if #changed>0 then
        local s=changed[1].address
        local last=s
        for i=2,#changed do
            local a2=changed[i].address
            if a2-last>5 then
                ranges[#ranges+1]={start=s,finish=last}
                s=a2
            end
            last=a2
        end
        ranges[#ranges+1]={start=s,finish=last}
    end

    local detailed=arr()
    for _,r in ipairs(ranges) do
        local s=math.max(CAL_START,r.start-4)
        local e=math.min(CAL_CAPTURE_END,r.finish+4)
        local n=e-s+1
        detailed[#detailed+1]={
            changed_start=r.start,changed_end=r.finish,
            context_start=s,context_end=e,
            before_hex=bytes_hex(a,s,n),
            after_hex=bytes_hex(b,s,n)
        }
    end
    return changed,detailed
end

local function output_path()
    local directory=tostring(EFI_ScriptName or ""):match("^(.*[\\/])") or FALLBACK_DIRECTORY
    if not directory then error("EFI_ScriptName must contain the script directory") end
    local stamp=os.date("%Y%m%d_%H%M%S")
    for n=1,9999 do
        local p=directory.."AL5_TARGETED_DIFFERENTIAL_MAP_"..stamp..string.format("_%03d.json",n)
        local f,err,code=io.open(p,"rb")
        if f then f:close()
        elseif code==2 then return p
        else error("Cannot check output path: "..tostring(err)) end
    end
    error("No unused output filename")
end


local cases = {
    {id="D5042",column=0,row=0,expected=3657,target=1200,columns=1,rows=1,label="Bidi Control Disable, 3rd Gear"},
    {id="D5043",column=0,row=0,expected=4000,target=1204,columns=1,rows=1,label="Bidi Control Disable, 4th Gear"},
    {id="D5044",column=0,row=0,expected=4000,target=1208,columns=1,rows=1,label="Bidi Control Disable, 5th Gear"},
    {id="D5045",column=0,row=0,expected=4000,target=1212,columns=1,rows=1,label="Bidi Control Disable, 6th Gear"},
    {id="D5055",column=0,row=0,expected=29,target=44,columns=1,rows=1,label="TCC Enable Min Temp Enable"},
    {id="D5056",column=0,row=0,expected=31,target=45,columns=1,rows=1,label="TCC Enable Min Temp Disable"},
    {id="D5057",column=0,row=0,expected=900,target=1224,columns=1,rows=1,label="TCC Enable Min RPM Enable"},
    {id="D5058",column=0,row=0,expected=1050,target=1228,columns=1,rows=1,label="TCC Enable Min RPM Disable"},
    {id="D5061",column=0,row=0,expected=2.7199726528000001,target=3,columns=1,rows=1,label="Transfer Case Ratio"},
    {id="D5062",column=0,row=0,expected=-8192,target=1236,columns=1,rows=1,label="Mod Main Pressure(G-Sol)  High RPM"},
    {id="D5063",column=0,row=0,expected=-8192,target=1240,columns=1,rows=1,label="Mod Main Pressure (G-Sol) Low RPM"},
    {id="D5183",column=0,row=0,expected=254,target=123,columns=1,rows=1,label="TCM Locked Counter"},
    {id="H0103",column=0,row=0,expected=4.099853515625,target=4.5,columns=1,rows=1,label="Final Drive Ratio"},
    {id="H0105",column=0,row=0,expected=2485.4839968000001,target=3000,columns=1,rows=1,label="ECM Pulses Per {du,count/km=kilometer,count/mile=mile,else=distance traveled}"},
    {id="H0136",column=0,row=0,expected=424,target=450,columns=1,rows=1,label="Tire Revolutions Per {du,rev/km=kilometer,rev/mile=mile,else=distance traveled}"},
    {id="H0137",column=0,row=0,expected=262.79138906730003,target=300,columns=1,rows=1,label="Vehicle Speed Ratio"},
    {id="D5073",column=0,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="1st Gear / 0"},
    {id="D5073",column=0,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="1st Gear / 128"},
    {id="D5073",column=0,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="1st Gear / 256"},
    {id="D5073",column=1,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="2nd Gear / 0"},
    {id="D5073",column=1,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="2nd Gear / 128"},
    {id="D5073",column=1,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="2nd Gear / 256"},
    {id="D5073",column=2,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="3rd Gear / 0"},
    {id="D5073",column=2,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="3rd Gear / 128"},
    {id="D5073",column=2,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="3rd Gear / 256"},
    {id="D5073",column=3,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="4th Gear / 0"},
    {id="D5073",column=3,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="4th Gear / 128"},
    {id="D5073",column=3,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="4th Gear / 256"},
    {id="D5073",column=4,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="5th Gear / 0"},
    {id="D5073",column=4,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="5th Gear / 128"},
    {id="D5073",column=4,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="5th Gear / 256"},
    {id="D5074",column=0,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="1st Gear / 0"},
    {id="D5074",column=0,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="1st Gear / 128"},
    {id="D5074",column=0,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="1st Gear / 256"},
    {id="D5074",column=1,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="2nd Gear / 0"},
    {id="D5074",column=1,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="2nd Gear / 128"},
    {id="D5074",column=1,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="2nd Gear / 256"},
    {id="D5074",column=2,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="3rd Gear / 0"},
    {id="D5074",column=2,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="3rd Gear / 128"},
    {id="D5074",column=2,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="3rd Gear / 256"},
    {id="D5074",column=3,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="4th Gear / 0"},
    {id="D5074",column=3,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="4th Gear / 128"},
    {id="D5074",column=3,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="4th Gear / 256"},
    {id="D5074",column=4,row=0,expected=99.998474124370489,target=50,columns=5,rows=17,label="5th Gear / 0"},
    {id="D5074",column=4,row=8,expected=99.998474124370489,target=50,columns=5,rows=17,label="5th Gear / 128"},
    {id="D5074",column=4,row=16,expected=99.998474124370489,target=50,columns=5,rows=17,label="5th Gear / 256"},
    {id="D5075",column=0,row=0,expected=0,target=50,columns=5,rows=17,label="1st Gear / 0"},
    {id="D5075",column=0,row=8,expected=0,target=50,columns=5,rows=17,label="1st Gear / 128"},
    {id="D5075",column=0,row=16,expected=0,target=50,columns=5,rows=17,label="1st Gear / 256"},
    {id="D5075",column=1,row=0,expected=0,target=50,columns=5,rows=17,label="2nd Gear / 0"},
    {id="D5075",column=1,row=8,expected=0,target=50,columns=5,rows=17,label="2nd Gear / 128"},
    {id="D5075",column=1,row=16,expected=0,target=50,columns=5,rows=17,label="2nd Gear / 256"},
    {id="D5075",column=2,row=0,expected=0,target=50,columns=5,rows=17,label="3rd Gear / 0"},
    {id="D5075",column=2,row=8,expected=0,target=50,columns=5,rows=17,label="3rd Gear / 128"},
    {id="D5075",column=2,row=16,expected=0,target=50,columns=5,rows=17,label="3rd Gear / 256"},
    {id="D5075",column=3,row=0,expected=0,target=50,columns=5,rows=17,label="4th Gear / 0"},
    {id="D5075",column=3,row=8,expected=0,target=50,columns=5,rows=17,label="4th Gear / 128"},
    {id="D5075",column=3,row=16,expected=0,target=50,columns=5,rows=17,label="4th Gear / 256"},
    {id="D5075",column=4,row=0,expected=0,target=50,columns=5,rows=17,label="5th Gear / 0"},
    {id="D5075",column=4,row=8,expected=0,target=50,columns=5,rows=17,label="5th Gear / 128"},
    {id="D5075",column=4,row=16,expected=0,target=50,columns=5,rows=17,label="5th Gear / 256"},
    {id="D5010",column=6,row=0,expected=32,target=100,columns=8,rows=17,label="Pattern G / 0"},
    {id="D5010",column=6,row=8,expected=32,target=100,columns=8,rows=17,label="Pattern G / 50"},
    {id="D5010",column=6,row=16,expected=45,target=100,columns=8,rows=17,label="Pattern G / 100"},
    {id="D5015",column=6,row=0,expected=26,target=100,columns=8,rows=17,label="Pattern G / 0"},
    {id="D5015",column=6,row=8,expected=26,target=100,columns=8,rows=17,label="Pattern G / 50"},
    {id="D5015",column=6,row=16,expected=38,target=100,columns=8,rows=17,label="Pattern G / 100"},
    {id="D5035",column=0,row=0,expected=20,target=100,columns=4,rows=2,label="Pattern A / High Value"},
    {id="D5035",column=0,row=1,expected=20,target=100,columns=4,rows=2,label="Pattern A / Low Value"},
    {id="D5035",column=3,row=0,expected=20,target=100,columns=4,rows=2,label="Pattern D / High Value"},
    {id="D5035",column=3,row=1,expected=20,target=100,columns=4,rows=2,label="Pattern D / Low Value"},
    {id="D5036",column=0,row=0,expected=45,target=100,columns=4,rows=2,label="Pattern A / High Value"},
    {id="D5036",column=0,row=1,expected=45,target=100,columns=4,rows=2,label="Pattern A / Low Value"},
    {id="D5036",column=3,row=0,expected=45,target=100,columns=4,rows=2,label="Pattern D / High Value"},
    {id="D5036",column=3,row=1,expected=45,target=100,columns=4,rows=2,label="Pattern D / Low Value"},
    {id="D5037",column=0,row=0,expected=62,target=100,columns=4,rows=2,label="Pattern A / High Value"},
    {id="D5037",column=0,row=1,expected=62,target=100,columns=4,rows=2,label="Pattern A / Low Value"},
    {id="D5037",column=3,row=0,expected=62,target=100,columns=4,rows=2,label="Pattern D / High Value"},
    {id="D5037",column=3,row=1,expected=62,target=100,columns=4,rows=2,label="Pattern D / Low Value"},
    {id="D5038",column=0,row=0,expected=100,target=123,columns=4,rows=2,label="Pattern A / High Value"},
    {id="D5038",column=0,row=1,expected=100,target=123,columns=4,rows=2,label="Pattern A / Low Value"},
    {id="D5038",column=3,row=0,expected=100,target=123,columns=4,rows=2,label="Pattern D / High Value"},
    {id="D5038",column=3,row=1,expected=100,target=123,columns=4,rows=2,label="Pattern D / Low Value"}
}
print("AL5 targeted mapper v6: offline, secondary descriptor only")
verify_identity(GUI_FD,"GUI source")
verify_baseline(GUI_FD)
local source=q(_efiGetFileProp,GUI_FD,11)
if type(source)~="string" or source=="" then error("Source path unavailable") end
local gui_raw,names,e=capture_raw_range(GUI_FD,nil)
if not gui_raw then error(e) end
if bytes_hex(gui_raw,0x0A996,12)~="11F70C68073E05A0040002D9" or
   bytes_hex(gui_raw,0x158A8,4)~="00110009" then error("Raw baseline anchors mismatch") end
local name_map=names_to_map(names)
local out=output_path() -- Validate report directory before opening/editing anything.
local fd,oe=q(_efiOpenFile,source)
if fd==nil then error("Secondary open failed: "..tostring(oe)) end
-- Never close or write a descriptor unless it is proven distinct from GUI 0.
if type(fd)~="number" or fd<=0 or fd~=math.floor(fd) then
    error("Unsafe secondary descriptor returned: "..tostring(fd))
end
local report={schema_version=1,tool="AL5-targeted-differential-mapper-0.6",
    controller="AL5",operating_system=EXPECTED_OS,transmission=EXPECTED_TRANS,
    source=source,created_local=os.date("%Y-%m-%dT%H:%M:%S"),
    gui_descriptor_modified=false,secondary_saved=false,vehicle_io=false,
    checksum_finalized=false,flash_ready=false,completed=false,
    raw_range={start=CAL_START,finish=CAL_CAPTURE_END,bytes=EXPECTED_CAPTURE_BYTES},
    cases=arr(),validation={}}
local ok,runerr=pcall(function()
    verify_identity(fd,"Secondary")
    verify_baseline(fd)
    local baseline,_,be=capture_raw_range(fd,name_map)
    if not baseline then error(be) end
    if baseline~=gui_raw then error("Secondary raw image differs from GUI baseline") end
    report.validation.secondary_baseline_equals_gui=true
    -- Preflight all dimensions and source values before the first edit.
    for _,x in ipairs(cases) do
        local h=get_cal(fd,x.id)
        if tonumber(q(_efiGetCalProp,h,30))~=x.columns or
           tonumber(q(_efiGetCalProp,h,31))~=x.rows then error(x.id.." dimensions mismatch") end
        if not near(get_value(fd,x.id,x.column,x.row),x.expected,0.001) then
            error(x.id.." native stock value mismatch")
        end
    end
    -- A known marker must appear at its proven address and restore exactly.
    local anchor=arr()
    set_cell(fd,anchor,"D5000",0,0,123,"coherency_anchor")
    local marked,_,me=capture_raw_range(fd,name_map)
    if not marked then error(me) end
    if bytes_hex(marked,0x11D0C,2)~="3D80" then error("Raw views do not reflect edits") end
    assert(q(_efiSetCalValue,get_cal(fd,"D5000"),0,0,16))
    local restored,_,re=capture_raw_range(fd,name_map)
    if not restored then error(re) end
    if restored~=baseline then error("Coherency restore changed raw baseline") end
    report.validation.raw_coherency_and_restore=true
    for i,x in ipairs(cases) do
        print(string.format("Case %d/%d %s c=%d r=%d",i,#cases,x.id,x.column,x.row))
        local m=arr()
        local before,after=set_cell(fd,m,x.id,x.column,x.row,x.target,x.label)
        if not tonumber(after) or near(before,after,1e-6) then error("Marker did not change "..x.id) end
        local raw,_,ce=capture_raw_range(fd,name_map)
        if not raw then error(ce) end
        local changed,ranges=make_diff_ranges(baseline,raw)
        local record={marker=m[1],changed_bytes=changed,diff_ranges=ranges,
            changed_byte_count=#changed,restored=false}
        report.cases[#report.cases+1]=record
        if #changed==0 then error("No raw changes for "..x.id) end
        assert(q(_efiSetCalValue,get_cal(fd,x.id),x.column,x.row,before))
        if not near(get_value(fd,x.id,x.column,x.row),before,0.001) then error("Cell restore failed") end
        local clean,_,cle=capture_raw_range(fd,name_map)
        if not clean then error(cle) end
        if clean~=baseline then error("Raw restoration failed for "..x.id.."; possible coupled controls") end
        record.restored=true
    end
    local final_gui,_,ge=capture_raw_range(GUI_FD,name_map)
    if not final_gui then error(ge) end
    if final_gui~=gui_raw then error("GUI raw memory changed during run") end
    report.validation.gui_raw_unchanged=true
    report.completed=true
end)
if not ok then report.error=tostring(runerr) end
local closed,ce=q(_efiCloseFile,fd)
report.secondary_closed=closed~=nil
if closed==nil then report.close_error=tostring(ce) end
local f,fe=io.open(out,"wb")
if not f then error("Cannot create report: "..tostring(fe)) end
f:write(json(report),"\n")
f:close()
print("Report: "..out)
if not ok then error(runerr) end
if closed==nil then error("Secondary close failed; discard without saving: "..tostring(ce)) end
print("Complete. GUI untouched; secondary discarded; no tune save or vehicle I/O.")
return 0
