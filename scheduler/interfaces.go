package scheduler

type runCrontabInterface interface {
	runCrontab(arguments ...string) (string, error)
}

