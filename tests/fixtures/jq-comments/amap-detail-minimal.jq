# Synthetic reproduction of the upstream comment layout, not a source patch.
def keep_module:
  IN(
    "baseInfo", # Keep the place itself.
    "anchor"    # Keep navigation within the detail page.
  );            # End of the helper.

if (.data | type) == "object" then
  (if (.data.modules | type) == "object" then
     .data.modules |= with_entries(select(.key | keep_module))
   else . end)
  | (if (.data.regions | type) == "array" then
       .data.regions |= map(select((type != "string") or keep_module))
     else . end)
else . end # End-of-file comments are valid JQ.
