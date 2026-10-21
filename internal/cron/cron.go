// Package cron implements a minimal 5-field cron expression parser.
package cron

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Schedule is a parsed cron expression.
type Schedule struct {
	minutes map[int]bool
	hours   map[int]bool
	days    map[int]bool
	months  map[int]bool
	dows    map[int]bool
	// domRestricted/dowRestricted follow standard cron semantics: when both
	// day-of-month and day-of-week are restricted the day matches if either
	// matches; otherwise both must match.
	domRestricted bool
	dowRestricted bool
	expr          string
}

// Parse parses a 5-field cron expression: minute hour day-of-month month day-of-week.
func Parse(expr string) (*Schedule, error) {
	fields := strings.Fields(expr)
	if len(fields) != 5 {
		return nil, fmt.Errorf("cron expression must have 5 fields, got %d", len(fields))
	}
	minutes, err := parseField(fields[0], 0, 59)
	if err != nil {
		return nil, fmt.Errorf("minute: %w", err)
	}
	hours, err := parseField(fields[1], 0, 23)
	if err != nil {
		return nil, fmt.Errorf("hour: %w", err)
	}
	days, err := parseField(fields[2], 1, 31)
	if err != nil {
		return nil, fmt.Errorf("day-of-month: %w", err)
	}
	months, err := parseField(fields[3], 1, 12)
	if err != nil {
		return nil, fmt.Errorf("month: %w", err)
	}
	dows, err := parseField(fields[4], 0, 6)
	if err != nil {
		return nil, fmt.Errorf("day-of-week: %w", err)
	}
	return &Schedule{
		minutes:       minutes,
		hours:         hours,
		days:          days,
		months:        months,
		dows:          dows,
		domRestricted: isRestricted(fields[2]),
		dowRestricted: isRestricted(fields[4]),
		expr:          expr,
	}, nil
}

// isRestricted reports whether a cron field constrains the value set.
func isRestricted(field string) bool {
	return strings.TrimSpace(field) != "*" && strings.TrimSpace(field) != "*/1"
}

// Expr returns the original expression.
func (s *Schedule) Expr() string { return s.expr }

// Next returns the first matching time strictly after `after`.
func (s *Schedule) Next(after time.Time) (time.Time, error) {
	t := after.Truncate(time.Minute).Add(time.Minute)
	// A year of minutes covers every possible schedule.
	for i := 0; i < 366*24*60; i++ {
		if s.matches(t) {
			return t, nil
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, fmt.Errorf("no matching time found within one year")
}

func (s *Schedule) matches(t time.Time) bool {
	if !s.minutes[t.Minute()] || !s.hours[t.Hour()] || !s.months[int(t.Month())] {
		return false
	}
	dom := s.days[t.Day()]
	dow := s.dows[int(t.Weekday())]
	if s.domRestricted && s.dowRestricted {
		return dom || dow
	}
	return dom && dow
}

// parseField parses a single cron field into the set of allowed values.
func parseField(field string, min, max int) (map[int]bool, error) {
	result := make(map[int]bool)
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, fmt.Errorf("empty value")
		}
		step := 1
		if strings.Contains(part, "/") {
			pieces := strings.SplitN(part, "/", 2)
			part = pieces[0]
			s, err := strconv.Atoi(pieces[1])
			if err != nil || s < 1 {
				return nil, fmt.Errorf("invalid step %q", pieces[1])
			}
			step = s
		}
		var lo, hi int
		switch {
		case part == "*":
			lo, hi = min, max
		case strings.Contains(part, "-"):
			pieces := strings.SplitN(part, "-", 2)
			l, err := strconv.Atoi(pieces[0])
			if err != nil {
				return nil, fmt.Errorf("invalid range start %q", pieces[0])
			}
			h, err := strconv.Atoi(pieces[1])
			if err != nil {
				return nil, fmt.Errorf("invalid range end %q", pieces[1])
			}
			lo, hi = l, h
		default:
			v, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid value %q", part)
			}
			lo, hi = v, v
		}
		if lo < min || hi > max || lo > hi {
			return nil, fmt.Errorf("value out of range [%d,%d]", min, max)
		}
		for i := lo; i <= hi; i += step {
			result[i] = true
		}
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("empty field")
	}
	return result, nil
}
