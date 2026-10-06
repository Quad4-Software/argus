import subprocess
# subprocess.run("ls", shell=True) in a comment must not fire
cmd = "cat {}".format(user_path)
subprocess.run(cmd, shell=True)
subprocess.run(["cat", user_path])
