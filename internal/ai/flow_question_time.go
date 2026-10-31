// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package ai

import (
	"math/big"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // Deterministic air-gapped IANA zones for standalone planners.
)

func questionLocation(name string) (*time.Location, error) {
	if name == "" {
		return time.UTC, nil
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return nil, errQuestionClause
	}
	return location, nil
}

func (c *questionCursor) integer() (int, error) {
	text, err := c.literal()
	if err != nil {
		return 0, err
	}
	value, err := strconv.ParseUint(text, 10, 64)
	if err != nil || value > uint64(^uint(0)>>1) {
		return 0, errQuestionClause
	}
	return int(value), nil
}

func (c *questionCursor) positiveInteger() (int, error) {
	value, err := c.integer()
	if err != nil || value < 1 {
		return 0, errQuestionClause
	}
	return value, nil
}

func (c *questionCursor) prefixLength() (int, error) {
	if c.position < len(c.tokens) && !c.tokens[c.position].quoted && strings.HasPrefix(c.tokens[c.position].text, "/") {
		text := strings.TrimPrefix(c.tokens[c.position].text, "/")
		value, err := strconv.ParseUint(text, 10, 8)
		if err != nil {
			return 0, errQuestionClause
		}
		c.position++
		return int(value), nil
	}
	return c.integer()
}

// Limit arithmetic by its representable duration, not an arbitrary history
// window. Reject exponents before big.Rat can expand them. Redundant zeroes
// are removed before constructing the small exact rational.
func questionDecimal(text string) (*big.Rat, error) {
	whole, fraction, hasPoint := strings.Cut(text, ".")
	if whole == "" && (!hasPoint || fraction == "") {
		return nil, errQuestionClause
	}
	for _, part := range []string{whole, fraction} {
		for _, digit := range part {
			if digit < '0' || digit > '9' {
				return nil, errQuestionClause
			}
		}
	}
	whole = strings.TrimLeft(whole, "0")
	fraction = strings.TrimRight(fraction, "0")
	if len(whole) > 19 || len(fraction) > 18 {
		return nil, errQuestionClause
	}
	if whole == "" {
		whole = "0"
	}
	canonical := whole
	if fraction != "" {
		canonical += "." + fraction
	}
	value, ok := new(big.Rat).SetString(canonical)
	if !ok || value.Sign() <= 0 {
		return nil, errQuestionClause
	}
	return value, nil
}

func (c *questionCursor) duration() (time.Duration, error) {
	text, err := c.literal()
	if err != nil {
		return 0, err
	}
	value, err := questionDecimal(text)
	if err != nil {
		return 0, err
	}
	unit, ok := questionTimeUnits[c.peekWord()]
	if !ok {
		return 0, errQuestionClause
	}
	c.position++
	value.Mul(value, new(big.Rat).SetInt64(int64(unit)))
	if !value.IsInt() || !value.Num().IsInt64() || value.Sign() <= 0 {
		return 0, errQuestionClause
	}
	return time.Duration(value.Num().Int64()), nil
}

func (c *questionCursor) peekWord() string {
	if c.position >= len(c.tokens) || c.tokens[c.position].quoted {
		return ""
	}
	return c.tokens[c.position].lower
}

var questionTimeUnits = map[string]time.Duration{
	"second": time.Second, "seconds": time.Second, "sec": time.Second, "secs": time.Second,
	"minute": time.Minute, "minutes": time.Minute, "min": time.Minute, "mins": time.Minute,
	"hour": time.Hour, "hours": time.Hour, "hr": time.Hour, "hrs": time.Hour,
	"day": 24 * time.Hour, "days": 24 * time.Hour, "week": 7 * 24 * time.Hour, "weeks": 7 * 24 * time.Hour,
}

func (c *questionCursor) instant(location *time.Location) (time.Time, error) {
	text, err := c.literal()
	if err != nil {
		return time.Time{}, err
	}
	if instant, err := time.Parse(time.RFC3339Nano, text); err == nil {
		return instant.UTC(), nil
	}
	date, err := time.Parse("2006-01-02", text)
	if err != nil {
		return time.Time{}, errQuestionClause
	}
	return questionWallTime(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, location)
}

func questionWallTime(year int, month time.Month, day, hour, minute, second, nanos int, location *time.Location) (time.Time, error) {
	value := time.Date(year, month, day, hour, minute, second, nanos, location)
	sameWall := func(candidate time.Time) bool {
		candidate = candidate.In(location)
		return candidate.Year() == year && candidate.Month() == month && candidate.Day() == day && candidate.Hour() == hour && candidate.Minute() == minute && candidate.Second() == second && candidate.Nanosecond() == nanos
	}
	if year < 1 || year > 9999 || !sameWall(value) {
		return time.Time{}, errQuestionClause
	}
	_, offset := value.Zone()
	for _, probe := range []time.Time{value.Add(-48 * time.Hour), value.Add(48 * time.Hour)} {
		_, other := probe.Zone()
		if other != offset && sameWall(value.Add(time.Duration(offset-other)*time.Second)) {
			return time.Time{}, errQuestionClause
		}
	}
	return value.UTC(), nil
}

func (c *questionCursor) period(now time.Time, location *time.Location) (FlowQuestionPeriod, error) {
	if c.accept("from") || c.accept("between") {
		from, err := c.instant(location)
		if err != nil {
			return FlowQuestionPeriod{}, err
		}
		if !c.accept("to") && !c.accept("until") && !c.accept("and") {
			return FlowQuestionPeriod{}, errQuestionClause
		}
		to, err := c.instant(location)
		if err != nil || !from.Before(to) {
			if err != nil {
				return FlowQuestionPeriod{}, err
			}
			return FlowQuestionPeriod{}, errQuestionClause
		}
		return FlowQuestionPeriod{From: from, To: to}, nil
	}
	if c.at("today") || c.at("yesterday") || c.at("this week") || c.at("last week") || c.at("previous week") || c.at("this month") || c.at("last month") || c.at("previous month") || c.at("this year") || c.at("last year") || c.at("previous year") {
		return c.calendarPeriod(now, location)
	}
	if !c.accept("last") && !c.accept("past") && !c.accept("previous") {
		return FlowQuestionPeriod{}, errQuestionClause
	}
	start := c.position
	count, err := c.integer()
	if err == nil && (c.at("month") || c.at("months") || c.at("year") || c.at("years")) {
		unit := c.peekWord()
		c.position++
		if count < 1 || count > 9999 {
			return FlowQuestionPeriod{}, errQuestionClause
		}
		local := now.In(location)
		year, month := local.Year(), local.Month()
		if strings.HasPrefix(unit, "year") {
			year -= count
		} else {
			first := time.Date(year, month, 1, 12, 0, 0, 0, time.UTC).AddDate(0, -count, 0)
			year, month = first.Year(), first.Month()
		}
		lastDay := time.Date(year, month+1, 0, 12, 0, 0, 0, time.UTC).Day()
		from, err := questionWallTime(year, month, min(local.Day(), lastDay), local.Hour(), local.Minute(), local.Second(), local.Nanosecond(), location)
		if err != nil {
			return FlowQuestionPeriod{}, err
		}
		return FlowQuestionPeriod{From: from, To: now.UTC()}, nil
	}
	c.position = start
	duration, err := c.duration()
	if err != nil {
		return FlowQuestionPeriod{}, err
	}
	from := now.Add(-duration)
	if from.Year() < 1 {
		return FlowQuestionPeriod{}, errQuestionClause
	}
	return FlowQuestionPeriod{From: from.UTC(), To: now.UTC()}, nil
}

func (c *questionCursor) calendarPeriod(now time.Time, location *time.Location) (FlowQuestionPeriod, error) {
	local := now.In(location)
	year, month, day := local.Date()
	previous := false
	unit := "day"
	switch {
	case c.accept("today"):
	case c.accept("yesterday"):
		previous = true
	default:
		previous = c.accept("last") || c.accept("previous")
		if !previous && !c.accept("this") {
			return FlowQuestionPeriod{}, errQuestionClause
		}
		unit = c.peekWord()
		c.position++
	}
	switch unit {
	case "week":
		weekday := (int(local.Weekday()) + 6) % 7
		date := time.Date(year, month, day, 12, 0, 0, 0, time.UTC).AddDate(0, 0, -weekday)
		year, month, day = date.Date()
	case "month":
		day = 1
	case "year":
		month, day = time.January, 1
	case "day":
	default:
		return FlowQuestionPeriod{}, errQuestionClause
	}
	boundary := time.Date(year, month, day, 12, 0, 0, 0, time.UTC)
	endYear, endMonth, endDay := year, month, day
	if previous {
		switch unit {
		case "day":
			boundary = boundary.AddDate(0, 0, -1)
		case "week":
			boundary = boundary.AddDate(0, 0, -7)
		case "month":
			boundary = boundary.AddDate(0, -1, 0)
		case "year":
			boundary = boundary.AddDate(-1, 0, 0)
		}
		year, month, day = boundary.Date()
	}
	from, err := questionWallTime(year, month, day, 0, 0, 0, 0, location)
	if err != nil {
		return FlowQuestionPeriod{}, err
	}
	to := now.UTC()
	if previous {
		to, err = questionWallTime(endYear, endMonth, endDay, 0, 0, 0, 0, location)
	}
	if err != nil || !from.Before(to) {
		return FlowQuestionPeriod{}, errQuestionClause
	}
	return FlowQuestionPeriod{From: from, To: to}, nil
}
