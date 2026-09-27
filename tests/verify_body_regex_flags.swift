// Compare Loon V2 flags with the explicit modifiers under Surge's multiline default.
import Foundation

let patterns = [
    #"^ad$"#, #"^(ad)(.*)$"#, #"a.b"#,
    #"(?s:begin.*end)$"#, #"(?i:(foo))|(?-i:(BAR))"#,
    #"(?x) ^ (ad) $ # trailing comment"#,
    #"^(café|straße|ﬃ)$"#,
]
let bodies = [
    "ad", "AD", "before\nad\nafter", "ad\nAD", "ad\r\nother",
    "a\nb", "a\rb", "a\u{2028}b", "axb", "begin\nend",
    "foo BAR bar FOO", "", "CAFÉ", "STRASSE", "FFI",
]
var comparisons = 0
for flags in ["", "i", "m", "s", "im", "is", "ms", "ims"] {
    var options: NSRegularExpression.Options = []
    if flags.contains("i") { options.insert(.caseInsensitive) }
    if flags.contains("m") { options.insert(.anchorsMatchLines) }
    if flags.contains("s") { options.insert(.dotMatchesLineSeparators) }
    let disabled = "ims".filter { !flags.contains($0) }
    let modifier = flags + (disabled.isEmpty ? "" : "-" + disabled)
    for pattern in patterns {
        let original = try NSRegularExpression(pattern: pattern, options: options)
        let converted = try NSRegularExpression(pattern: "(?\(modifier))\(pattern)", options: [.anchorsMatchLines])
        for body in bodies {
            let range = NSRange(body.startIndex..., in: body)
            let before = original.matches(in: body, range: range)
            let after = converted.matches(in: body, range: range)
            precondition(before.count == after.count, "Match count changed: /\(pattern)/\(flags), \(body)")
            for (left, right) in zip(before, after) {
                precondition(left.numberOfRanges == right.numberOfRanges, "Capture count changed")
                for group in 0..<left.numberOfRanges {
                    precondition(left.range(at: group) == right.range(at: group), "Capture changed")
                }
            }
            let replacement = original.numberOfCaptureGroups > 0 ? "<$0:$1>" : "<$0>"
            precondition(
                original.stringByReplacingMatches(in: body, range: range, withTemplate: replacement)
                    == converted.stringByReplacingMatches(in: body, range: range, withTemplate: replacement),
                "Replacement changed"
            )
            comparisons += 1
        }
    }
}
print("Foundation/ICU Body Rewrite flags: \(comparisons) comparisons passed.")
