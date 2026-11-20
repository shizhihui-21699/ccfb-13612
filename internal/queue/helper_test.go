package queue

import "os"

func writeFile(dir, name, content string) error {
	return os.WriteFile(dir+"/"+name, []byte(content), 0o600)
}
