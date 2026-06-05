-- headings.lua
-- Pipeline:
--   * Header()  annotates each heading with data-section="N.M" and fails the
--     build on duplicate ids (slug ids are preserved; uniqueness is asserted).
--   * Blocks()  inserts, after each heading, a raw-html anchor link that CSS
--     reveals on hover. The anchor is a sibling of the heading, not a child,
--     so it does NOT contaminate pandoc's table of contents text.
--
-- Deterministic, no external state. No JavaScript emitted.

local seen_ids = {}

local function extract_section_number(inlines)
  if #inlines == 0 then return nil end
  local first = inlines[1]
  if first.t ~= "Str" then return nil end
  local prefix = first.text:match("^(%d[%d%.]*)%.?$")
  if prefix == nil then return nil end
  prefix = prefix:gsub("%.$", "")
  if prefix == "" then return nil end
  for part in prefix:gmatch("[^.]+") do
    if #part > 3 then return nil end
  end
  return prefix
end

function Header(el)
  local id = el.identifier
  if id == nil or id == "" then
    return el
  end
  if seen_ids[id] then
    io.stderr:write(
      string.format("headings.lua: duplicate heading id '%s' (F-006 guardrail)\n", id)
    )
    os.exit(1)
  end
  seen_ids[id] = true

  local section_number = extract_section_number(el.content)
  if section_number ~= nil then
    el.attributes["data-section"] = section_number
  end

  return el
end

-- After Header() annotates, this Blocks filter walks the block list and
-- inserts a raw-html permalink anchor immediately after every heading.
function Blocks(blocks)
  local out = {}
  for _, block in ipairs(blocks) do
    table.insert(out, block)
    if block.t == "Header" and block.identifier and block.identifier ~= "" then
      local html = string.format(
        '<a class="anchor" href="#%s" aria-label="Permalink to this section">#</a>',
        block.identifier
      )
      table.insert(out, pandoc.RawBlock("html", html))
    end
  end
  return out
end
