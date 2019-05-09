package database

// newestFirst implements sort.Interface for []RequestToJoinTeamMessage based on
// the RequestedAt field.
type newestFirst []RequestToJoinTeamMessage

func (a newestFirst) Len() int           { return len(a) }
func (a newestFirst) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a newestFirst) Less(i, j int) bool { return a[i].RequestedAt.After(a[j].RequestedAt) }
