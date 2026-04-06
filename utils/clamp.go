package utils

import "cmp"

func Clamp[T cmp.Ordered](value, minValue, maxValue T) T {
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}
