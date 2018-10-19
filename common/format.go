// Copyright 2018 The go-hpb Authors
// This file is part of the go-hpb.
//
// The go-hpb is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-hpb is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-hpb. If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PrettyDuration is a pretty printed version of a time.Duration value that cuts
// the unnecessary precision off from the formatted textual representation.
type PrettyDuration time.Duration

var prettyDurationRe = regexp.MustCompile(`\.[0-9]+`)

// String implements the Stringer interface, allowing pretty printing of duration
// values rounded to three decimals.
func (d PrettyDuration) String() string {
	label := fmt.Sprintf("%v", time.Duration(d))
	if match := prettyDurationRe.FindString(label); len(match) > 4 {
		label = strings.Replace(label, match, match[:4], 1)
	}
	return label
}

func IsAddrHas0xPre(str string) bool {
	pat := "(0x)([0-9a-f]{40})([^0-9a-f]{1}|$)(.*)?"
	if ok, _ := regexp.Match(pat, []byte(str)); ok {
		return true
	} else {
		return false
	}
}

func RexRep0xToHpb(str *string) string {
	pat := "(0x)([0-9a-f]{40})([^0-9a-f]{1}|$)(.*)?"
	if ok, _ := regexp.Match(pat, []byte(*str)); ok {

		re, _ := regexp.Compile(pat)
		sub := re.FindSubmatch([]byte(*str))
		if len(sub) == 5 {
			*str = re.ReplaceAllString(*str, "hpb"+string(sub[2])+string(sub[3])+string(sub[4]))
		}
		RexRep0xToHpb(str)
	}

	return *str
}

func RexRepHpbTo0x(str *string) string {
	pat := "(hpb)([0-9a-f]{40})([^0-9a-f]{1}|$)(.*)?"
	if ok, _ := regexp.Match(pat, []byte(*str)); ok {

		re, _ := regexp.Compile(pat)
		sub := re.FindSubmatch([]byte(*str))
		if len(sub) == 5 {
			*str = re.ReplaceAllString(*str, "0x"+string(sub[2])+string(sub[3])+string(sub[4]))
		}
		RexRepHpbTo0x(str)
	}

	return *str
}
