/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2020 WireGuard LLC. All Rights Reserved.
 */

package conf

import (
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"golang.zx2c4.com/wireguard/windows/conf/dpapi"
)

const configFileSuffix = ".conf.dpapi"
const configFileUnencryptedSuffix = ".conf"

var serviceName string

func ListConfigNames() ([]string, error) {
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return nil, err
	}
	files, err := ioutil.ReadDir(configFileDir)
	if err != nil {
		return nil, err
	}
	configs := make([]string, len(files))
	i := 0
	for _, file := range files {
		name := filepath.Base(file.Name())
		if len(name) <= len(configFileSuffix) || !strings.HasSuffix(name, configFileSuffix) {
			continue
		}
		if !file.Mode().IsRegular() || file.Mode().Perm()&0444 == 0 {
			continue
		}
		name = strings.TrimSuffix(name, configFileSuffix)
		if !TunnelNameIsValid(name) {
			continue
		}
		configs[i] = name
		i++
	}
	return configs[:i], nil
}

func LoadFromName(name string) (*Config, error) {
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return nil, err
	}
	return LoadFromPath(filepath.Join(configFileDir, name+configFileSuffix))
}

func LoadFromString(configText string, name string) (*Config, error) {
	return FromWgQuickWithUnknownEncoding(string([]byte(configText)), name)
}

func LoadFromPath(path string) (*Config, error) {
	name, err := NameFromPath(path)
	if err != nil {
		return nil, err
	}
	bytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if strings.HasSuffix(path, configFileSuffix) {
		bytes, err = dpapi.Decrypt(bytes, name)
		if err != nil {
			return nil, err
		}
	}
	return FromWgQuickWithUnknownEncoding(string(bytes), name)
}

func PathIsEncrypted(path string) bool {
	return strings.HasSuffix(filepath.Base(path), configFileSuffix)
}

func NameFromPath(path string) (string, error) {
	return GetServiceName(), nil
	// name := filepath.Base(path)
	// if !((len(name) > len(configFileSuffix) && strings.HasSuffix(name, configFileSuffix)) ||
	// 	(len(name) > len(configFileUnencryptedSuffix) && strings.HasSuffix(name, configFileUnencryptedSuffix))) {
	// 	return "", errors.New("Path must end in either " + configFileSuffix + " or " + configFileUnencryptedSuffix)
	// }
	// if strings.HasSuffix(path, configFileSuffix) {
	// 	name = strings.TrimSuffix(name, configFileSuffix)
	// } else {
	// 	name = strings.TrimSuffix(name, configFileUnencryptedSuffix)
	// }
	// if !TunnelNameIsValid(name) {
	// 	return "", errors.New("Tunnel name is not valid")
	// }
	// return name, nil
}

func GetServiceName() (string) {
	return serviceName;
}

func SetServiceName(serviceAndAdapterName string){
	serviceName = serviceAndAdapterName
}

func (config *Config) Save(overwrite bool) error {
	if !TunnelNameIsValid(config.Name) {
		return errors.New("Tunnel name is not valid")
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	filename := filepath.Join(configFileDir, config.Name+configFileSuffix)
	bytes := []byte(config.ToWgQuick())
	bytes, err = dpapi.Encrypt(bytes, config.Name)
	if err != nil {
		return err
	}
	return writeLockedDownFile(filename, overwrite, bytes)
}

func (config *Config) Path() (string, error) {
	if !TunnelNameIsValid(config.Name) {
		return "", errors.New("Tunnel name is not valid")
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(configFileDir, config.Name+configFileSuffix), nil
}

func DeleteName(name string) error {
	if !TunnelNameIsValid(name) {
		return errors.New("Tunnel name is not valid")
	}
	configFileDir, err := tunnelConfigurationsDirectory()
	if err != nil {
		return err
	}
	return os.Remove(filepath.Join(configFileDir, name+configFileSuffix))
}

func (config *Config) Delete() error {
	return DeleteName(config.Name)
}
