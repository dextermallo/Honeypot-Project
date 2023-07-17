package container

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/dexter/owasp-honeypot/utils/logger"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
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

func Diff(containerName string, ignoredRegexList []string) error {
	logger.Debug("start container.Diff()")

	ctx := context.Background()

	changes, err := svcClient.ContainerDiff(ctx, containerName)

	if err != nil {
		logger.Error(err.Error())
		return err
	}

	res := []interface{}{}

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

	fmt.Println(res)
	return nil
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
