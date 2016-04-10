// Package cafe provides golang API for cafe.naver.com
package cafe

import "time"

// Cafe represents a single Naver Cafe community.
type Cafe struct {
	BoardList
	ClubID   uint64
	ClubName string

	Name string
}

// BoardList is a group of Categories.
type BoardList []Category

// Category is a group of boards.
type Category struct {
	Name   string
	Boards []Board
}

// Board is a list of articles.
type Board struct {
	ID uint64
}

// Article represents a single Naver Cafe post.
type Article struct {
	By       Member
	When     time.Time
	Document string
}

// Member represents a single community member.
type Member struct {
	NaverID string
}
