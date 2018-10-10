package status

// ByActionType implements sort.Interface for []KeyAction based on
// the SortOrder field.
type ByActionType []KeyAction

func (a ByActionType) Len() int           { return len(a) }
func (a ByActionType) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByActionType) Less(i, j int) bool { return a[i].SortOrder() < a[j].SortOrder() }
