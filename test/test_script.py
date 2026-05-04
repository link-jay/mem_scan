import subprocess
import time

ret = subprocess.run(". ../venv/bin/activate && "
                     "mypy /home/rudyous/Programs/mem_scan/mem_scan.py", shell=True);
if ret.returncode != 0:
    print(ret)
    exit(ret.returncode)


null = open("/dev/null", "w");
test_task = subprocess.Popen("./test.out",
                             shell=True, stdout=null)
pid = str(test_task.pid)
time.sleep(1)

main_task = subprocess.Popen(". ../venv/bin/activate && "
                             "python ../mem_scan.py --debug " + pid,
                             shell=True, bufsize=0, stdin=subprocess.PIPE, text=True)

with open("/home/rudyous/Programs/mem_scan/test/commands.txt") as cmds:
    for cmd in cmds:
        if cmd[0] == '#': continue
        main_task.stdin.write(cmd)
        main_task.stdin.flush()
main_task.stdin.close()
main_task.wait();

main_task.terminate();
main_task.wait();
test_task.terminate();
test_task.wait();
exit(main_task.returncode)
