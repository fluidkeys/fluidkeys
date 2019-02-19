package scheduler

type runCrontabInterface interface {
	get() (string, error)
	set(newCrontab string) error
}
