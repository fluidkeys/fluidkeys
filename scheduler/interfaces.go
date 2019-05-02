package scheduler

type runCrontabInterface interface {
	get() (string, error)
	set(newCrontab string) error
}

type runLaunchctlInterface interface {
	load(filename string) (string, error)
	remove(label string) (string, error)
}
