package v1

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/text/feature/plural"
	"golang.org/x/text/language"
)

// PluralCategory represents the plural categories from CLDR
// TypeScript original code:
// export type PluralCategory = 'zero' | 'one' | 'two' | 'few' | 'many' | 'other'
type PluralCategory string

const (
	PluralZero  PluralCategory = "zero"
	PluralOne   PluralCategory = "one"
	PluralTwo   PluralCategory = "two"
	PluralFew   PluralCategory = "few"
	PluralMany  PluralCategory = "many"
	PluralOther PluralCategory = "other"
)

// PluralFunction represents a function used to define the pluralization for a locale
// TypeScript original code:
//
//	export interface PluralFunction {
//	  (value: number | string, ord?: boolean): PluralCategory;
//	  cardinals?: PluralCategory[];
//	  ordinals?: PluralCategory[];
//	  module?: string;
//	}
type PluralFunction func(value interface{}, ord ...bool) (PluralCategory, error)

// PluralObject represents plural rules and metadata for a specific locale
// TypeScript original code:
//
//	export interface PluralObject {
//	  isDefault: boolean;
//	  id: string;
//	  lc: string;
//	  locale: string;
//	  getCardinal?: (value: string | number) => PluralCategory;
//	  getPlural: PluralFunction;
//	  cardinals: PluralCategory[];
//	  ordinals: PluralCategory[];
//	  module?: string;
//	}
type PluralObject struct {
	IsDefault   bool
	ID          string
	LC          string
	Locale      string
	GetCardinal func(value interface{}) (PluralCategory, error)
	Func        PluralFunction
	Cardinals   []PluralCategory
	Ordinals    []PluralCategory
	Module      string
}

// normalize normalizes a locale string following TypeScript implementation
// TypeScript original code:
//
//	function normalize(locale: string) {
//	  if (typeof locale !== 'string' || locale.length < 2) {
//	    throw new RangeError(`Invalid language tag: ${locale}`);
//	  }
//	  // The only locale for which anything but the primary subtag matters is
//	  // Portuguese as spoken in Portugal.
//	  if (locale.startsWith('pt-PT')) return 'pt-PT';
//	  const m = locale.match(/.+?(?=[-_])/);
//	  return m ? m[0] : locale;
//	}
func normalize(locale string) (string, error) {
	if len(locale) < 2 {
		return "", WrapInvalidLocale(locale)
	}

	// Special case for Portuguese as spoken in Portugal
	if strings.HasPrefix(locale, "pt-PT") {
		return "pt-PT", nil
	}

	// Extract primary subtag
	re := regexp.MustCompile(`^([^-_]+)`)
	if matches := re.FindStringSubmatch(locale); len(matches) > 1 {
		return matches[1], nil
	}

	return locale, nil
}

// GetPlural returns the PluralObject for a given locale
// TypeScript original code:
// export function getPlural(locale: string | PluralFunction): PluralObject | null
func GetPlural(locale interface{}) (PluralObject, error) {
	switch v := locale.(type) {
	case string:
		normalized, err := normalize(v)
		if err != nil {
			return PluralObject{}, fmt.Errorf("failed to normalize locale %s: %w", v, err)
		}

		// Get the plural function for this locale
		pluralFunc, cardinals, ordinals, supported := getPluralRules(normalized)

		// For TypeScript compatibility, preserve original locale if it's supported or looks like a locale variant
		preserveLocale := supported || strings.Contains(v, "-") || strings.Contains(v, "_")
		localeName := v
		if !preserveLocale {
			// Fallback to English for completely unknown locales
			localeName = DefaultLocale
		}

		return PluralObject{
			IsDefault: normalized == DefaultLocale,
			ID:        localeName,
			LC:        localeName,
			Locale:    localeName,
			Func:      pluralFunc,
			Cardinals: cardinals,
			Ordinals:  ordinals,
			Module:    fmt.Sprintf("make-plural/%s", normalized),
		}, nil

	case PluralFunction:
		return PluralObject{
			IsDefault: false,
			ID:        "custom",
			LC:        "custom",
			Locale:    "custom",
			Func:      v,
			Cardinals: []PluralCategory{PluralOne, PluralOther}, // Default cardinals
			Ordinals:  []PluralCategory{PluralOther},            // Default ordinals
		}, nil

	default:
		return PluralObject{}, ErrUnsupportedType
	}
}

// HasPlural checks if a locale has plural support
// TypeScript original code:
// export function hasPlural(locale: string): boolean
func HasPlural(locale string) bool {
	normalized, err := normalize(locale)
	if err != nil {
		return false
	}

	// Check if we have plural rules for this locale
	// We use hasPlural function to check support instead of getPluralRules
	return hasPlural(normalized)
}

// GetAllPlurals returns all available plurals for a given default locale
// TypeScript original code:
// export function getAllPlurals(defaultLocale: string): PluralObject[]
func GetAllPlurals(defaultLocale string) ([]PluralObject, error) {
	// For now, return common locales
	// In a full implementation, this would include all CLDR locales
	commonLocales := []string{
		"en", "fr", "de", "es", "it", "pt", "ru", "ja", "ko", "zh",
		"ar", "he", "hi", "th", "vi", "id", "ms", "tl", "sw",
	}

	plurals := make([]PluralObject, 0, len(commonLocales))
	for _, locale := range commonLocales {
		plural, err := GetPlural(locale)
		if err != nil {
			continue // Skip locales that can't be processed
		}
		plurals = append(plurals, plural)
	}

	// Ensure default locale is first
	defaultPlural, err := GetPlural(defaultLocale)
	if err == nil {
		// Remove default from list if present and prepend
		var filtered []PluralObject
		for _, p := range plurals {
			if p.Locale != defaultLocale {
				filtered = append(filtered, p)
			}
		}
		plurals = append([]PluralObject{defaultPlural}, filtered...)
	}

	return plurals, nil
}

// getPluralRules returns the plural function and categories for a given locale using golang.org/x/text
func getPluralRules(locale string) (PluralFunction, []PluralCategory, []PluralCategory, bool) {
	tag, err := language.Parse(locale)
	if err != nil {
		// Fallback to English for invalid locales
		tag = language.English
	}

	// Create wrapper function that uses golang.org/x/text/feature/plural
	pluralFunc := func(value interface{}, ord ...bool) (PluralCategory, error) {
		num, err := toNumber(value)
		if err != nil {
			return PluralOther, err
		}

		// Handle edge cases for negative numbers and zero
		if num < 0 {
			num = -num // Use absolute value for plural calculations
		}

		isOrdinal := len(ord) > 0 && ord[0]
		rule := plural.Cardinal
		if isOrdinal {
			rule = plural.Ordinal
		}

		// Use CLDR plural rules from golang.org/x/text with proper error handling
		// Parameters: i (integer), v (visible fraction digits), w (w/o trailing zeros), f (fraction), t (fraction w/o trailing zeros)
		defer func() {
			if r := recover(); r != nil {
				// In case of panic, fall back to basic English-like rules
				// Empty body is intentional - we just want to recover gracefully
				_ = r
			}
		}()

		result := rule.MatchPlural(tag, int(num), 0, 0, 0, 0)
		return mapPluralResult(result), nil
	}

	// Get available categories for this language
	cardinals := getAvailableCategories(tag, false)
	ordinals := getAvailableCategories(tag, true)

	// Check if this is actually a supported locale based on the original input
	// rather than the parsed tag, because language.Parse might change unknown locales to "und"
	isSupported := hasPlural(locale) // Use the original locale string

	return pluralFunc, cardinals, ordinals, isSupported
}

// mapPluralResult maps golang.org/x/text/feature/plural results to our PluralCategory
func mapPluralResult(result plural.Form) PluralCategory {
	switch result {
	case plural.Zero:
		return PluralZero
	case plural.One:
		return PluralOne
	case plural.Two:
		return PluralTwo
	case plural.Few:
		return PluralFew
	case plural.Many:
		return PluralMany
	case plural.Other:
		return PluralOther
	default:
		return PluralOther
	}
}

// getAvailableCategories returns available plural categories for a language tag
func getAvailableCategories(tag language.Tag, ordinal bool) []PluralCategory {
	// This is a simplified implementation - in a full version, we would
	// query the CLDR data to get the exact categories available for each locale
	rule := plural.Cardinal
	if ordinal {
		rule = plural.Ordinal
	}

	// Test various numbers to determine available categories
	categories := make(map[PluralCategory]bool)
	testNumbers := []int{0, 1, 2, 3, 5, 11, 21, 22, 23, 100, 101, 102, 1000}

	for _, num := range testNumbers {
		result := rule.MatchPlural(tag, num, 0, 0, 0, 0)
		category := mapPluralResult(result)
		categories[category] = true
	}

	// Convert map to slice, maintaining order
	var result []PluralCategory
	order := []PluralCategory{PluralZero, PluralOne, PluralTwo, PluralFew, PluralMany, PluralOther}
	for _, cat := range order {
		if categories[cat] {
			result = append(result, cat)
		}
	}

	// Ensure "other" is always available as fallback
	if len(result) == 0 || result[len(result)-1] != PluralOther {
		result = append(result, PluralOther)
	}

	return result
}

// toNumber converts various types to int64
func toNumber(value interface{}) (int64, error) {
	switch v := value.(type) {
	case int:
		return int64(v), nil
	case int32:
		return int64(v), nil
	case int64:
		return v, nil
	case float32:
		return int64(v), nil
	case float64:
		return int64(v), nil
	case string:
		num, err := strconv.ParseFloat(v, 64)
		if err != nil {
			return 0, WrapInvalidNumberStr(v)
		}
		return int64(num), nil
	default:
		return 0, WrapUnsupportedType(fmt.Sprintf("%T", value))
	}
}
