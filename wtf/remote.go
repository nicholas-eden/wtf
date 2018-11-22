package wtf

import (
	"fmt"
	"github.com/labstack/gommon/log"
	"github.com/rivo/tview"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"io/ioutil"
	"net"
	"os"
	"os/user"
)

type Remote struct {
	Host     string
	Port     int
	User     string
	KeyFile  string
	Password string
	*ssh.Client
}

func NewRemote(app *tview.Application, configKey string) Remote {
	var username string
	u, err := user.Current()
	if err == nil {
		username = u.Username
	}

	remote := Remote{
		Host:     Config.UString(fmt.Sprintf("wtf.mods.%s.remote.host", configKey), "localhost"),
		Port:     Config.UInt(fmt.Sprintf("wtf.mods.%s.remote.port", configKey), 22),
		User:     Config.UString(fmt.Sprintf("wtf.mods.%s.remote.user", configKey), username),
		KeyFile:  Config.UString(fmt.Sprintf("wtf.mods.%s.remote.key", configKey), "~/.ssh/id_rsa"),
		Password: Config.UString(fmt.Sprintf("wtf.mods.%s.remote.password", configKey), ),
	}

	return remote
}

func (r *Remote) Connect() (*ssh.Client, error) {
	sshConfig := &ssh.ClientConfig{
		User: r.User,
		Auth: []ssh.AuthMethod{},
	}

	if len(r.Password) > 0 {
		sshConfig.Auth = append(sshConfig.Auth, ssh.Password(r.Password))
	}

	if len(r.KeyFile) > 0 {
		if key, err := publicKeyFile(r.KeyFile); err == nil {
			sshConfig.Auth = append(sshConfig.Auth, key)
		}
	}

	if a, err := sshAgent(); err == nil {
		sshConfig.Auth = append(sshConfig.Auth, a)
	}

	client, err := ssh.Dial("tcp", r.Host + string(r.Port), sshConfig)
	if err != nil {
		log.Fatalf("Failed to connect to remote host %s: %s", r.Host, err)
		return nil, err
	}

	r.Client = client

	return client, nil
}

func publicKeyFile(file string) (ssh.AuthMethod, error) {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil, err
	}

	return ssh.PublicKeys(key), nil
}

func sshAgent() (ssh.AuthMethod, error) {
	sshAgent, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}
	return ssh.PublicKeysCallback(agent.NewClient(sshAgent).Signers), nil
}

