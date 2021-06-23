package service

import (
	"bufio"
	"fmt"
	"free5gc/lib/http2_util"
	"free5gc/lib/logger_util"
	"free5gc/lib/path_util"
	"free5gc/src/app"
	"free5gc/src/naf/consumer"
	naf_context "free5gc/src/naf/context"
	"free5gc/src/naf/factory"
	"free5gc/src/naf/logger"
	"free5gc/src/naf/ueauthentication"
	"free5gc/src/naf/util"
	"os/exec"
	"sync"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

type NAF struct{}

type (
	// Config information.
	Config struct {
		nafcfg string
	}
)

var config Config

var nafCLi = []cli.Flag{
	cli.StringFlag{
		Name:  "free5gccfg",
		Usage: "common config file",
	},
	cli.StringFlag{
		Name:  "nafcfg",
		Usage: "config file",
	},
}

var initLog *logrus.Entry

func init() {
	initLog = logger.InitLog
}

func (*NAF) GetCliCmd() (flags []cli.Flag) {
	return nafCLi
}

func (*NAF) Initialize(c *cli.Context) {

	config = Config{
		nafcfg: c.String("nafcfg"),
	}

	if config.nafcfg != "" {
		factory.InitConfigFactory(config.nafcfg)
	} else {
		DefaultNafConfigPath := path_util.Gofree5gcPath("free5gc/config/nafcfg.conf")
		factory.InitConfigFactory(DefaultNafConfigPath)
	}

	if app.ContextSelf().Logger.NAF.DebugLevel != "" {
		level, err := logrus.ParseLevel(app.ContextSelf().Logger.NAF.DebugLevel)
		if err != nil {
			initLog.Warnf("Log level [%s] is not valid, set to [info] level", app.ContextSelf().Logger.NAF.DebugLevel)
			logger.SetLogLevel(logrus.InfoLevel)
		} else {
			logger.SetLogLevel(level)
			initLog.Infof("Log level is set to [%s] level", level)
		}
	} else {
		initLog.Infoln("Log level is default set to [info] level")
		logger.SetLogLevel(logrus.InfoLevel)
	}

	logger.SetReportCaller(app.ContextSelf().Logger.NAF.ReportCaller)

}

func (naf *NAF) FilterCli(c *cli.Context) (args []string) {
	for _, flag := range naf.GetCliCmd() {
		name := flag.GetName()
		value := fmt.Sprint(c.Generic(name))
		if value == "" {
			continue
		}

		args = append(args, "--"+name, value)
	}
	return args
}

func (naf *NAF) Start() {
	initLog.Infoln("Server started")

	router := logger_util.NewGinWithLogrus(logger.GinLog)
	ueauthentication.AddService(router)

	naf_context.Init()
	self := naf_context.GetSelf()
	// Register to NRF
	profile, err := consumer.BuildNFInstance(self)
	if err != nil {
		initLog.Error("Build NAF Profile Error")
	}
	_, self.NfId, err = consumer.SendRegisterNFInstance(self.NrfUri, self.NfId, profile)
	if err != nil {
		initLog.Errorf("NAF register to NRF Error[%s]", err.Error())
	}

	nafLogPath := util.NafLogPath

	addr := fmt.Sprintf("%s:%d", self.BindingIPv4, self.SBIPort)

	server, err := http2_util.NewServer(addr, nafLogPath, router)
	if server == nil {
		initLog.Errorf("Initialize HTTP server failed: %+v", err)
		return
	}

	if err != nil {
		initLog.Warnf("Initialize HTTP server: +%v", err)
	}

	serverScheme := factory.NafConfig.Configuration.Sbi.Scheme
	if serverScheme == "http" {
		err = server.ListenAndServe()
	} else if serverScheme == "https" {
		err = server.ListenAndServeTLS(util.NafPemPath, util.NafKeyPath)
	}

	if err != nil {
		initLog.Fatalf("HTTP server setup failed: %+v", err)
	}
}

func (naf *NAF) Exec(c *cli.Context) error {

	initLog.Traceln("args:", c.String("nafcfg"))
	args := naf.FilterCli(c)
	initLog.Traceln("filter: ", args)
	command := exec.Command("./naf", args...)

	stdout, err := command.StdoutPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	wg := sync.WaitGroup{}
	wg.Add(3)
	go func() {
		in := bufio.NewScanner(stdout)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	stderr, err := command.StderrPipe()
	if err != nil {
		initLog.Fatalln(err)
	}
	go func() {
		in := bufio.NewScanner(stderr)
		for in.Scan() {
			fmt.Println(in.Text())
		}
		wg.Done()
	}()

	go func() {
		startErr := command.Start()
		if startErr != nil {
			initLog.Fatalln(startErr)
		}
		wg.Done()
	}()

	wg.Wait()

	return err
}
