package transaction

// GenerateScript parse given params to script
func GenerateScript(hash string, operation string, args []interface{}, useTailCall bool) string {
	script := Script{"", hash, operation, args}
	script.serielize(useTailCall)
	return script.script
}
