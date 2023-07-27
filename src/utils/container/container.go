package container

import (
	"context"
	"fmt"
	"regexp"

	"github.com/dextermallo/owasp-honeypot/utils/logger"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

var (
	svcClient *client.Client
)

func init() {
	c, err := client.NewClientWithOpts(client.FromEnv)
	svcClient = c

	if err != nil {
		fmt.Printf("Unable to create docker client: %s", err)
	}
}

func IsRunning(containerID string) (bool, error) {
	logger.Debug("start container.IsRunning()")
	ctx := context.Background()
	inspect, err := svcClient.ContainerInspect(ctx, containerID)

	if err != nil {
		logger.Error(err.Error())
		return false, err
	}

	return inspect.State.Running, nil
}

func Restart(containerName string) error {
	logger.Debug("start container.Restart()")
	ctx := context.Background()
	err := svcClient.ContainerRestart(ctx, containerName, nil)
	return err
}

func Remove(containerID string) error {
	logger.Debug("start container.Remove()")

	ctx := context.Background()
	err := svcClient.ContainerStop(ctx, containerID, nil)

	if err != nil {
		return err
	}

	return svcClient.ContainerRemove(ctx, containerID, types.ContainerRemoveOptions{})
}

func Disconnect(networkID string, containerID string) error {
	logger.Debug("start container.Disconnect()")
	ctx := context.Background()
	return svcClient.NetworkDisconnect(ctx, networkID, containerID, true)
}

func Connect(networkID string, containerID string) error {
	logger.Debug("start container.Connect()")
	ctx := context.Background()
	return svcClient.NetworkConnect(ctx, networkID, containerID, nil)
}

func Diff(containerName string, ignoredRegexList []string) ([]interface{}, error) {
	logger.Debug("start container.Diff()")

	ctx := context.Background()

	changes, err := svcClient.ContainerDiff(ctx, containerName)
	res := []interface{}{}

	if err != nil {
		logger.Error(err.Error())
		return res, err
	}

	for _, change := range changes {
		excluded := false
		for _, regex := range ignoredRegexList {
			pattern := regexp.MustCompile(regex)
			if pattern.MatchString(change.Path) {
				excluded = true
				break
			}
		}

		if !excluded {
			res = append(res, change)
		}
	}

	return res, nil
}

func ReinstallHoneypot(id string, networkID string) error {
	logger.Info("start container.Create()")
	ctx := context.Background()
	HOME_DIR := "/Users/dexter"

	if isRunning, _ := IsRunning("honeypot-" + id); isRunning {
		logger.Info("Container is already running")
		Remove("honeypot-" + id)
	}

	_, err := svcClient.ContainerCreate(
		ctx,
		&container.Config{
			Image:        "justsky/honeypots",
			Tty:          true,
			Cmd:          []string{"--setup", "http"},
			ExposedPorts: nat.PortSet{"80/tcp": struct{}{}},
		},
		&container.HostConfig{
			NetworkMode: container.NetworkMode(networkID),
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: HOME_DIR + "/log/honeypot/" + id,
					Target: "/honeypots/logs",
				},
			},
			PortBindings: nat.PortMap{
				"80/tcp": []nat.PortBinding{
					{
						HostPort: "800" + id,
					},
				},
			},
		},
		nil,
		&v1.Platform{},
		"honeypot-"+id,
	)

	if err != nil {
		logger.Error(err.Error())
		return err
	}

	err = svcClient.ContainerStart(ctx, "honeypot-"+id, types.ContainerStartOptions{})
	return err
}
