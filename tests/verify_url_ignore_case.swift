// macOS: swift tests/verify_url_ignore_case.swift
// Compare Foundation/ICU ignore-case options with the emitted scoped modifier.
import Foundation

let patterns = [
    #"^https:\/\/api\.example\.com\/(Ads|Banner)/(\d+)$"#,
    #"^https:\/\/api\.example\.com\/ads\b"#,
    #"^https:\/\/api\.example\.com\/(?<item>ads|banner)\?key=(\w+)$"#,
    #"^https:\/\/api\.example\.com\/(?i:ads)/(?-i:Exact)$"#,
    #"^https:\/\/api\.example\.com\/café$"#,
]
let urls = [
    "https://api.example.com/Ads/12", "HTTPS://API.EXAMPLE.COM/bANNER/34",
    "https://api.example.com/other/12", "https://other.example.com/Ads/12",
    "https://api.example.com/ads", "https://api.example.com/ADS?key=X",
    "https://api.example.com/ADSERVER", "https://api.example.com/ADS/Exact",
    "https://api.example.com/ADS/exact", "https://api.example.com/CAFÉ",
    "https://api.example.com/ads\nhttps://other.example.com/banner",
]
var comparisons = 0
for pattern in patterns {
    let original = try NSRegularExpression(pattern: pattern, options: [.caseInsensitive])
    let converted = try NSRegularExpression(pattern: "(?i:\(pattern))")
    for url in urls {
        let range = NSRange(url.startIndex..., in: url)
        let before = original.matches(in: url, range: range)
        let after = converted.matches(in: url, range: range)
        precondition(before.count == after.count, "Match count changed: \(pattern), \(url)")
        for (left, right) in zip(before, after) {
            precondition(left.numberOfRanges == right.numberOfRanges, "Capture count changed")
            for group in 0..<left.numberOfRanges {
                precondition(left.range(at: group) == right.range(at: group), "Capture changed")
            }
        }
        comparisons += 1
    }
}
print("Foundation/ICU ignore-case equivalence: \(comparisons) comparisons passed.")
