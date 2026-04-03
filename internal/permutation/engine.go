package permutation

import (
	"strings"
	"unicode"

	"sandman-osint/internal/query"
)

const maxVariants = 60

// Generate produces all search variants for a raw input and target type.
func Generate(raw string, t query.TargetType) []string {
	raw = strings.TrimSpace(raw)
	switch t {
	case query.TargetPerson:
		return personVariants(raw)
	case query.TargetUsername:
		return usernameVariants(raw)
	case query.TargetCompany:
		return companyVariants(raw)
	default:
		return dedup([]string{normalize(raw)})
	}
}

// personVariants handles full names ("John Doe") and email addresses.
func personVariants(raw string) []string {
	var variants []string

	// Email input
	if strings.Contains(raw, "@") {
		parts := strings.SplitN(raw, "@", 2)
		local := parts[0]
		variants = append(variants, raw)
		// Derive name variants from the local part
		nameGuess := strings.NewReplacer(".", " ", "_", " ", "-", " ").Replace(local)
		variants = append(variants, personVariants(nameGuess)...)
		return dedup(variants)
	}

	parts := strings.Fields(raw)
	if len(parts) == 0 {
		return dedup([]string{normalize(raw)})
	}

	if len(parts) == 1 {
		n := normalize(parts[0])
		variants = append(variants, n)
		variants = append(variants, usernameVariants(n)...)
		return dedup(variants)
	}

	first := normalize(parts[0])
	last := normalize(parts[len(parts)-1])
	fi := string([]rune(first)[0]) // first initial
	li := string([]rune(last)[0])  // last initial

	// Username-style permutations
	variants = append(variants,
		first+last,         // johndoe
		first+"."+last,     // john.doe
		first+"_"+last,     // john_doe
		first+"-"+last,     // john-doe
		fi+last,            // jdoe
		fi+"."+last,        // j.doe
		fi+"_"+last,        // j_doe
		fi+"-"+last,        // j-doe
		last+first,         // doejohn
		last+"."+first,     // doe.john
		last+"_"+first,     // doe_john
		last+fi,            // doej
		first+li,           // johndo
		first,              // john
		last,               // doe
	)

	// Email permutations across common free providers
	freeDomains := []string{
		"gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
		"protonmail.com", "icloud.com",
	}
	nameForEmail := []string{
		first + "." + last,
		first + last,
		fi + last,
		fi + "." + last,
		first + "_" + last,
		last + "." + first,
	}
	for _, n := range nameForEmail {
		for _, d := range freeDomains {
			variants = append(variants, n+"@"+d)
		}
	}

	return cap(dedup(variants))
}

// usernameVariants generates handle permutations from a raw username.
func usernameVariants(raw string) []string {
	n := normalize(raw)
	base := strings.NewReplacer("-", "", "_", "", ".", "").Replace(n)

	variants := []string{
		n,
		base,
		strings.ReplaceAll(n, "-", "_"),
		strings.ReplaceAll(n, "_", "-"),
		strings.ReplaceAll(n, "-", "."),
		n + "_",
		"_" + n,
		"real" + n,
		"the" + n,
		n + "1",
		n + "dev",
		n + "hq",
		n + "official",
		n + "real",
	}

	// Leet-speak reverse: 3→e, 4→a, 0→o, 1→i
	leetMap := map[rune]rune{
		'3': 'e', '4': 'a', '0': 'o', '1': 'i', '@': 'a', '$': 's', '!': 'i',
	}
	decoded := make([]rune, 0, len(n))
	changed := false
	for _, r := range n {
		if d, ok := leetMap[r]; ok {
			decoded = append(decoded, d)
			changed = true
		} else {
			decoded = append(decoded, r)
		}
	}
	if changed {
		variants = append(variants, string(decoded))
	}

	return cap(dedup(variants))
}

// companyVariants generates slug, domain, and handle permutations for a company name.
func companyVariants(raw string) []string {
	n := normalize(raw)

	// Strip common legal suffixes
	suffixes := []string{
		" incorporated", " corporation", " limited", " company",
		" inc", " llc", " ltd", " corp", " co", " gmbh", " sas", " ag", " bv", " plc",
	}
	stripped := n
	for _, suf := range suffixes {
		if strings.HasSuffix(stripped, suf) {
			stripped = strings.TrimSuffix(stripped, suf)
			break
		}
	}

	base := strings.ReplaceAll(stripped, " ", "")
	hyphen := strings.ReplaceAll(stripped, " ", "-")
	under := strings.ReplaceAll(stripped, " ", "_")

	variants := []string{
		base,
		hyphen,
		under,
		stripped,
		"the" + base,
		base + "inc",
		base + "hq",
		base + "io",
		base + "app",
		base + "api",
		n,
	}

	// Domain guesses
	tlds := []string{".com", ".io", ".co", ".net", ".org", ".app", ".dev"}
	for _, tld := range tlds {
		variants = append(variants, base+tld)
	}

	// Email domain patterns for Hunter.io
	variants = append(variants, "@"+base+".com", "@"+hyphen+".com")

	return cap(dedup(variants))
}

// normalize lowercases and strips non-OSINT-relevant characters.
func normalize(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) ||
			r == '-' || r == '_' || r == '.' || r == '@' || r == ' ' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func dedup(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func cap(in []string) []string {
	if len(in) > maxVariants {
		return in[:maxVariants]
	}
	return in
}
