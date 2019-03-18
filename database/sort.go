package database

// earliestFirst implements sort.Interface for []RequestToJoinTeamMessage based on
// the RequestedAt field.
type earliestFirst []RequestToJoinTeamMessage

func (a earliestFirst) Len() int           { return len(a) }
func (a earliestFirst) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a earliestFirst) Less(i, j int) bool { return a[i].RequestedAt.Before(a[j].RequestedAt) }
