-- A link's preview (RFC-0187 §3; README.md, "Short links and previews"): the Open Graph tags a
-- chat app or a social site reads from a link to one aircraft, /?icao=<hex> or
-- /?reg=<registration> (where the short links go), as adsb.lol's map writes them. nginx runs it in
-- index.html's access phase (nginx.conf); it leaves the tags in $preview and </head> in
-- $preview_head, and sub_filter puts the one before the other. Asked for no aircraft, or one it
-- cannot read, it leaves both empty and the page is served as it is.
--
-- The tags name the aircraft from readsb's answer for it, and their picture is the map at its
-- position (preview.py), which anyone reads on the map; the site's card when readsb hears it
-- nowhere, or always when TALLY_MAP_PREVIEWS is off (nginx's $previews). Nothing of a receiver:
-- none of the fields readsb writes of its own (r_dst, r_dir, rssi), which with the aircraft's
-- position would place one (crates/api/src/privacy.rs; this readsb has no receiver).
local cjson = require "cjson.safe"

-- The first of a parameter's comma-separated values (tar1090 takes a list), or nil.
local function first(value)
    if type(value) == "table" then
        value = value[1]
    end
    if type(value) ~= "string" then
        return nil
    end
    return value:match("^[^,]*")
end

local args = ngx.req.get_uri_args(32)
local hex, reg = first(args.icao), first(args.reg)
local query, name, asked
-- A hex is six hex digits, or tar1090's ~hex for an address that is not ICAO's.
if hex and hex:match("^~?%x%x%x%x%x%x$") then
    query, name, asked = "find_hex=" .. hex:lower(), hex:upper(), "icao=" .. hex:lower()
elseif reg and #reg <= 12 and reg:match("^%w[%w-]*$") then
    query, name, asked = "find_reg=" .. reg:upper(), reg:upper(), "reg=" .. reg:upper()
else
    return
end

-- A string field of readsb's answer, trimmed, or nil.
local function text(value)
    if type(value) ~= "string" then
        return nil
    end
    value = value:gsub("%c", ""):match("^%s*(.-)%s*$")
    if value == "" then
        return nil
    end
    return value
end

-- A whole number with thousands separated: 36,000.
local function thousands(value)
    local digits = tostring(math.floor(value + 0.5))
    return (digits:reverse():gsub("(%d%d%d)(%d)", "%1,%2"):reverse())
end

-- readsb's answer: its aircraft, false when it hears none, nil when it did not answer.
local aircraft
local answer = ngx.location.capture("/_readsb", { args = query .. "&jv2" })
if answer.status == 200 then
    local body = cjson.decode(answer.body)
    if type(body) == "table" and type(body.ac) == "table" then
        aircraft = type(body.ac[1]) == "table" and body.ac[1]
    end
end

-- The map's public origin, which a card's links must name in full: TALLY_MAP_URL, or this host
-- over https.
local origin = os.getenv("TALLY_MAP_URL")
if not origin or origin == "" then
    origin = "https://" .. ngx.var.host
end

-- The picture: the map at the aircraft's position, rounded to 0.01 degrees (about a kilometre),
-- which keys preview.py's cache; or the site's card, which is all there is with the pictures off.
local image, drawn = origin .. "/card.jpg", false
if ngx.var.previews ~= "off" and aircraft and type(aircraft.lat) == "number" and type(aircraft.lon) == "number"
    and type(aircraft.hex) == "string" and aircraft.hex:match("^~?%x%x%x%x%x%x$") then
    image = string.format("%s/preview/%s/%.2f,%.2f.jpg", origin, aircraft.hex:lower(), aircraft.lat, aircraft.lon)
    drawn = true
end

local title, description
if aircraft == nil then
    title, description = name, "On the map"
elseif aircraft then
    -- Its callsign, registration and type, each it has.
    local named = {}
    local kind = text(aircraft.desc) or text(aircraft.t)
    for _, field in ipairs({ text(aircraft.flight) or false, text(aircraft.r) or false, kind or false }) do
        if field then
            named[#named + 1] = field
        end
    end
    title = #named > 0 and table.concat(named, " · ") or name
    local said = {}
    if aircraft.alt_baro == "ground" then
        said[#said + 1] = "On the ground"
    elseif type(aircraft.alt_baro) == "number" then
        said[#said + 1] = thousands(aircraft.alt_baro) .. " ft"
    end
    if type(aircraft.gs) == "number" then
        said[#said + 1] = thousands(aircraft.gs) .. " kt"
    end
    description = #said > 0 and table.concat(said, " · ") or "Live on the map"
else
    title, description = name, "Not heard right now"
end

local site = text(os.getenv("TALLY_MAP_TITLE")) or "Tally"

-- An attribute's value: markup's own characters escaped.
local escapes = { ["&"] = "&amp;", ["<"] = "&lt;", [">"] = "&gt;", ['"'] = "&quot;", ["'"] = "&#39;" }
local function attribute(value)
    return (value:gsub("[&<>\"']", escapes))
end

ngx.var.preview = table.concat({
    '<meta property="og:type" content="website">',
    '<meta property="og:site_name" content="', attribute(site), '">',
    '<meta property="og:url" content="', attribute(origin .. "/?" .. asked), '">',
    '<meta property="og:title" content="', attribute(title), '">',
    '<meta property="og:description" content="', attribute(description), '">',
    '<meta property="og:image" content="', attribute(image), '">',
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
    '<meta property="og:image:alt" content="', attribute(drawn and title .. " on the map" or site), '">',
    '<meta name="twitter:card" content="summary_large_image">',
})
ngx.var.preview_head = "</head>"
