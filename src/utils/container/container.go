package container

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/dexter/owasp-honeypot/utils/logger"
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

// Stop and remove a container
func Remove(containerID string) error {
	logger.Debug("start container.Remove()")

	ctx := context.Background()

	err := svcClient.ContainerStop(ctx, containerID, nil)

	if err != nil {
		logger.Error(err.Error())
		return err
	}

	err = svcClient.ContainerRemove(
		ctx,
		containerID,
		types.ContainerRemoveOptions{})

	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}

func Disconnect(networkID string, containerID string) error {
	logger.Debug("start container.Disconnect()")

	ctx := context.Background()

	err := svcClient.NetworkDisconnect(
		ctx,
		networkID,
		containerID,
		true)

	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}

func Connect(networkID string, containerID string) error {
	logger.Debug("start container.Connect()")

	ctx := context.Background()

	err := svcClient.NetworkConnect(
		ctx,
		networkID,
		containerID,
		nil)

	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
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

func Restart(containerName string) error {
	logger.Debug("start container.Restart()")

	ctx := context.Background()

	err := svcClient.ContainerRestart(ctx, containerName, nil)

	if err != nil {
		logger.Error(err.Error())
		return err
	}

	return nil
}

func GetStats(containerName string) types.StatsJSON {
	logger.Debug("start container.getStats()")

	duration := 5 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()

	stats, err := svcClient.ContainerStats(ctx, containerName, false)
	if err != nil {
		logger.Fatal(err)
	}

	defer stats.Body.Close()
	var res types.StatsJSON

	dec := json.NewDecoder(stats.Body)
	err = dec.Decode(&res)

	if err != nil {
		logger.Fatal(err)
	}

	return res
}

func FullRestart(containerName string) error {
	logger.Debug("start container.FullRestart()")

	return nil
}

func CreateHoneypot() error {
	logger.Info("start container.Create()")
	ctx := context.Background()

	_, err := svcClient.ContainerCreate(
		ctx,
		&container.Config{
			Image:        "justsky/honeypots",
			Tty:          true,
			Cmd:          []string{"--setup", "all"},
			ExposedPorts: nat.PortSet{"80/tcp": struct{}{}},
		},
		&container.HostConfig{
			NetworkMode: container.NetworkMode("distributed-honeypot"),
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: "/Users/dexter/Desktop/GitHub/Honeypot-Project/logs/honeypot",
					Target: "/honeypots/logs",
				},
				{
					Type:   mount.TypeBind,
					Source: "/Users/dexter/Desktop/GitHub/Honeypot-Project/src/honeypot_config.json",
					Target: "/honeypots/config.json",
				},
			},
		},
		nil,
		&v1.Platform{},
		"honeypot")

	if err != nil {
		logger.Error(err.Error())
		return err
	}

	err = svcClient.ContainerStart(ctx, "honeypot", types.ContainerStartOptions{})

	if err != nil {
		logger.Error(err.Error())
		return err
	}
	return nil
}

// func CalculateCPUUsage(stats *types.StatsJSON) float64 {
// 	logger.Debug("start container.CalculateCPUUsage()")

// 	cpuDelta := float64(stats.CPUStats.CPUUsage.TotalUsage - stats.PreCPUStats.CPUUsage.TotalUsage)
// 	systemDelta := float64(stats.CPUStats.SystemUsage - stats.PreCPUStats.SystemUsage)

// 	core := float64(len(stats.CPUStats.CPUUsage.PercpuUsage))

// 	if core == 0 {
// 		core = 1
// 	}

// 	cpuUsage := (cpuDelta / systemDelta) * core * 100.0
// 	return cpuUsage
// }
