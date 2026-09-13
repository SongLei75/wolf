import logging
import paramiko
import os

from wolfssh_x509 import build_x509_auth_strategy

class xssh:
    def __init__(self, name, user, addr, port: int = 22, pswd: str = '',
                 log: logging = None, usex509: bool = False,
                 keyfile: str | None = None,
                 certfile: str | None = None, cafile: str | None = None):
        self.name = name
        self.user = user
        self.addr = addr
        self.port = port
        self.pswd = pswd
        self.log = log if log else logging.getLogger("paramiko")
        self.log.setLevel(logging.WARNING)
        self.ssh: paramiko.SSHClient
        self.usex509 = usex509
        self.keyfile = os.path.expanduser(keyfile) if keyfile else None
        self.certfile = certfile
        self.cafile = cafile

    def __init(self):
        """建立 SSH 连接"""
        try:
            self.ssh = paramiko.SSHClient()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            key_filename = self.keyfile
            config = None
            if os.path.exists(os.path.expanduser("~/.ssh/config")):
                config = paramiko.SSHConfig()
                with open(os.path.expanduser("~/.ssh/config")) as f:
                    config.parse(f)
                host_config = config.lookup(self.addr)
                if key_filename is None:
                    key_filename = host_config.get("identityfile", [None])[0]
                    key_filename = (
                        os.path.expanduser(key_filename) if key_filename else None
                    )
            else:
                print("SSH config file not found, using default settings.")

            self.log.debug(
                f"Connecting ssh channel {self.name} "
                f"by user:{self.user} addr: {self.addr} port: {self.port}, password: {self.pswd}"
            )

            self.ssh.connect(
                hostname=self.addr,
                port=self.port,
                username=self.user,
                password=self.pswd,
                key_filename=key_filename,
                timeout=30,
                auth_strategy=build_x509_auth_strategy(
                    username=self.user,
                    keyfile=key_filename,
                    certfile=self.certfile,
                    cafile=self.cafile,
                ) if self.usex509 else None,
            )
            self.log.debug(f'Succeed to connect ssh channel {self.name} '
                           f'by user:{self.user} addr: {self.addr} port: {self.port}, password: {self.pswd}')
        except Exception as e:
            self.log.error(f"SSH connection setup failed: {repr(e)}")
            return False

    def __deinit(self):
        if self.ssh is not None:
            self.ssh.close()

    def send_cmd(self, cmd: str, timeout, eols, interval):
        self.__init()
        output=''

        try:
            _, stdout, stderr = self.ssh.exec_command(cmd, timeout=timeout, get_pty=True)
            output += (stdout.read().decode('utf-8') + stderr.read().decode('utf-8'))
            result = True
        except Exception as e:
            self.log.error(f'Failed to execute command: {e}')
            result = False

        self.__deinit()
        return result, output

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[logging.StreamHandler(sys.stdout)],
    )

    HOST = "192.168.2.62"
    USER = "root"
    PORT = 22
    KEYFILE = "~/.ssh/debug.key"

    ssh = xssh(
        name="test-x509",
        user=USER,
        addr=HOST,
        port=PORT,
        pswd="",
        log=logging.getLogger(__name__),
        usex509=True,
        keyfile=KEYFILE,
    )
    result, output = ssh.send_cmd("uname -a", timeout=30, eols=[], interval=None)
    print(f"RESULT: {result}")
    print(f"OUTPUT: {output}")
