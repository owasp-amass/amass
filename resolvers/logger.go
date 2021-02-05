package resolvers

type Logger interface {
	Printf(format string, v ...interface{})
	Print(v ...interface{})
	Println(v ...interface{})
}
