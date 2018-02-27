import argparse
import re
import os
import shutil
import stat
import json
import subprocess
import multiprocessing
import prepare_all_cmd_for_ctu

def get_file_path(analyzer_command_file):
    with open(analyzer_command_file, 'r') as f:
        return f.read().split(" ")[-1]

def get_std_flag(str):
    std_flag_pattern = re.compile("-std=")
    l = str.split()
    for x in l:
        if std_flag_pattern.match(x):
            return x
    return ""

def get_preprocessed_repro_file(abs_file_path, analyzer_command_file):
    with open(analyzer_command_file, 'r') as f:
        cmd = f.read().split(" ")
        param_pattern = re.compile("-I|-D")
        prepoc_params = [x for x in cmd if param_pattern.match(x)]
        preproc = \
            subprocess.Popen(["gcc", "-E"] + prepoc_params + [abs_file_path],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = preproc.communicate()
        filename = abs_file_path.split('/')[-1]
        # assuming exactly one dot (.) in the file name
        prepoc_name = filename.split('.')[0] + "_preproc." + \
            filename.split('.')[1]
    with open(prepoc_name, 'w') as preproc_file:
        preproc_file.write(out)
    return prepoc_name


def get_assertion_string(analyzer_command_file):
    error = subprocess.Popen(["bash", analyzer_command_file],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    _, error_string = error.communicate()
    assert_pattern = re.compile('Assertion.+failed\.')
    assert_match = assert_pattern.search(error_string)
    if not assert_match:
        return ""
    return assert_match.group(0)


def reduce(reduce_file, assert_string, analyzer_command_file, num_threads, stdflag):
    reduce_file_name = os.path.basename(reduce_file)
    #reduce_file_name = prepoc_name.replace("preproc", "reduce")
    #if not os.path.exists(reduce_file_name):
    #    shutil.copy2(prepoc_name, reduce_file_name)
    #else:
    #    return reduce_file_name
    conditions = []
    compilable_cond = ['gcc', '-c', '-Werror', stdflag, reduce_file_name]
    conditions.append(' '.join(compilable_cond))
    with open(analyzer_command_file, 'r') as f:
        ctu_analyze_fail_cond = f.read().split(" ")
    ctu_analyze_fail_cond[-1] = reduce_file_name
    ctu_pattern = re.compile("xtu|ctu|analyzer-config")
    normal_analyze_cond = []
    for x in ctu_analyze_fail_cond:
        if not ctu_pattern.search(x):
            normal_analyze_cond.append(x)
        else:
            normal_analyze_cond = normal_analyze_cond[:-1]
    conditions.append(' '.join(normal_analyze_cond))
    if assert_string:
        assert_string = assert_string.replace('\"', '\\\"').replace('`', '\\`')
        match_condition = ['grep', '-F', '\"' + assert_string + '\"']
        piping = ['2>&1', '>/dev/null', '|']
        ctu_analyze_fail_cond.extend(piping)
        ctu_analyze_fail_cond.extend(match_condition)
    else:
        ctu_analyze_fail_cond.insert(0, '!')

    ctu_analyze_fail_cond.insert(2, '-Werror=odr')

    conditions.append(' '.join(ctu_analyze_fail_cond))
    print "WRITING CREDUCE TEST_SH"
    # writing the test script for creduce
    creduce_test_name = 'creduce_test.sh'
    with open(creduce_test_name, 'w') as test:
        test.write("#!/bin/bash\n")
        test.write(' >/dev/null 2>&1 &&\\\n'.join(conditions))
    # make it executable
    st = os.stat(creduce_test_name)
    os.chmod(creduce_test_name, st.st_mode | stat.S_IEXEC)
    subprocess.call(['creduce', creduce_test_name,
                     reduce_file_name, '--n', str(num_threads)])

    return reduce_file_name


def reduce_dep(dep_file_abs_path, assert_string, analyzer_command_file, reduced_orig_file_name, stdflag):
    reduce_file_name = os.path.basename(dep_file_abs_path)
    print dep_file_abs_path
    ast_dump_path = os.path.join(os.path.abspath('./cc_files'), 'ctu-dir', 'x86_64', 'ast')
    #print ast_dump_path
    ast_dump_path = os.path.join(ast_dump_path, '.' + dep_file_abs_path + '.ast')
    #print ast_dump_path
    #return
    conditions = []
    compilable_cond = ['gcc', '-c', '-Werror', stdflag, reduce_file_name]
    conditions.append(' '.join(compilable_cond))
    ast_dump_cond = ['clang', stdflag, '-Xclang', '-emit-pch', '-o', ast_dump_path, '-c' ,reduce_file_name]
    conditions.append(' '.join(ast_dump_cond))
    with open(analyzer_command_file, 'r') as f:
        ctu_analyze_fail_cond = f.read().split(" ")
    ctu_analyze_fail_cond[-1] = os.path.abspath(reduced_orig_file_name)
    ctu_pattern = re.compile("xtu|ctu|analyzer-config")
    normal_analyze_cond = []
    for x in ctu_analyze_fail_cond:
        if not ctu_pattern.search(x):
            normal_analyze_cond.append(x)
        else:
            normal_analyze_cond = normal_analyze_cond[:-1]
    conditions.append(' '.join(normal_analyze_cond))
    if assert_string:
        assert_string = assert_string.replace('\"', '\\\"').replace('`', '\\`')
        match_condition = ['grep', '-F', '\"' + assert_string + '\"']
        piping = ['2>&1', '>/dev/null', '|']
        ctu_analyze_fail_cond.extend(piping)
        ctu_analyze_fail_cond.extend(match_condition)
    else:
        ctu_analyze_fail_cond.insert(0, '!')

    ctu_analyze_fail_cond.insert(2, '-Werror=odr')

    conditions.append(' '.join(ctu_analyze_fail_cond))
# writing the test script for creduce
    creduce_test_name = 'creduce_test.sh'
    with open(creduce_test_name, 'w') as test:
        test.write("#!/bin/bash\n")
        test.write(' >/dev/null 2>&1 &&\\\n'.join(conditions))
        st = os.stat(creduce_test_name)

    os.chmod(creduce_test_name, st.st_mode | stat.S_IEXEC)
    subprocess.call(['creduce', creduce_test_name,
                     dep_file_abs_path, '--n', '1'])


def get_new_cmd(old_cmd, file_dir_path):
    old_cmd = old_cmd.split(" ")
    new_cmd = []
    param_pattern = re.compile("-I|-D|-isystem")
    for x in old_cmd:
        if param_pattern.match(x):
            continue
        new_cmd.append(x)

    obj_ind = new_cmd.index('-o')
    new_cmd[obj_ind+1] = os.path.join(file_dir_path, os.path.basename(old_cmd[old_cmd.index('-o')+1]))

    file_name = os.path.basename(old_cmd[-1])
    new_cmd[-1] = os.path.join(file_dir_path, file_name)
    return ' '.join(new_cmd)


def get_new_analyzer_cmd(old_cmd, file_dir_path):
    old_cmd = old_cmd.split(" ")
    new_cmd = []
    param_pattern = re.compile("-I|-D")
    param_pattern2 = re.compile("-isystem")
    corresp = False
    for x in old_cmd:
        if param_pattern.match(x):
            continue
        if param_pattern2.match(x):
            corresp = True
            continue
        if corresp:
            corresp = False
            continue
        if re.match("xtu-dir", x):
            new_cmd.append('xtu-dir=' + os.path.join(file_dir_path, 'cc_files', 'ctu-dir', 'x86_64'))
            continue
        else:
            new_cmd.append(x)


    file_name = os.path.basename(old_cmd[-1])
    new_cmd[-1] = os.path.join(file_dir_path, file_name)
    return ' '.join(new_cmd)


def get_preprocessed_repro_file(abs_file_path, analyzer_command_file):
    with open(analyzer_command_file, 'r') as f:
        cmd = f.read().split(" ")
        param_pattern = re.compile("-I|-D")
        prepoc_params = [x for x in cmd if param_pattern.match(x)]
        preproc = \
            subprocess.Popen(["gcc", "-E"] + prepoc_params + [abs_file_path],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, _ = preproc.communicate()
        filename = abs_file_path.split('/')[-1]
        # assuming exactly one dot (.) in the file name
        prepoc_name = filename.split('.')[0] + "_preproc." + \
            filename.split('.')[1]
    with open(prepoc_name, 'w') as preproc_file:
        preproc_file.write(out)
    return prepoc_name


def get_preprocess_cmd(comp_cmd, repro_dir, filename):
    preproc_cmd = str(comp_cmd.decode("utf-8")).split(' ')
    preproc_cmd = filter(lambda x: not re.match('-c', x), preproc_cmd)
    preproc_cmd.insert(1, '-E')
    out_ind = preproc_cmd.index('-o')
    preproc_cmd[out_ind + 1] = os.path.join(repro_dir, filename)
    # preproc_cmd.extend(['>', str(file.decode("utf-8"))])
    return preproc_cmd


def main():
    parser = argparse.ArgumentParser(
        description='Reduces the reproduction files for CTU bugs.')
    parser.add_argument(
        '--analyzer-command',
        default='./analyzer-command_DEBUG',
        help="Path of the script which calls the analyzer"
             " resulting a CTU error.")
    parser.add_argument(
        '-j',
        default=multiprocessing.cpu_count(),
        help="Number of threads.")
    parser.add_argument(
        '--verbose',
        default=False,
        help="Verbose mode.")
    parser.add_argument(
        '--sources_root',
        default='./sources-root',
        help="Path of the source root.")
    parser.add_argument(
        '--report_dir',
        default='..',
        help="Path of the report dir.")
    parser.add_argument(
        '--fail-dir',
        default='./reports/failed',
        help="Path of the failures dir.")
    parser.add_argument(
        '--clang',
        required=True,
        help="Path to the clang binary.")
    parser.add_argument(
        '--clang_plugin_name', default=None,
        help="Name of the used clang plugin.")
    parser.add_argument(
        '--clang_plugin_path', default=None,
        help="Path to the used clang plugin.")
    parser.add_argument(
        '--repro_zip', default=None,
        help="The zip which contains the information needed for reproduction.")
    args = parser.parse_args()
    # change the paths to absolute
    args.sources_root = os.path.abspath(args.sources_root)
    args.fail_dir = os.path.abspath(args.fail_dir)
    pathOptions = prepare_all_cmd_for_ctu.PathOptions(
            args.sources_root,
            args.clang,
            args.clang_plugin_name,
            args.clang_plugin_path,
            args.report_dir)
    i = 1
    assert_string_set = set()
    for zip_repro in os.listdir(args.fail_dir):
        if not zip_repro.endswith(".zip") or not zip_repro.startswith("XSModelGroupDefinition.cpp_e1"):
            continue
        #if i <= 2:
        #    i+=1
        #    continue
        os.chdir(args.fail_dir)
        # print "ls | grep -P -v \"zip$|repro$\" | xargs -d\"\\n\" rm -r"
       
        print zip_repro
        repro_dir = os.path.abspath(os.path.join(args.fail_dir, zip_repro.split('.')[0] + "_repro"))
        print repro_dir
        analyzer_command_file = os.path.join(repro_dir, 'analyze.sh')
        if not os.path.exists(repro_dir):
            #collect and preprocess data phase
            print 'UNZIP'
            try:
                output = subprocess.check_output(['timeout', '3', 'unzip', zip_repro], stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError, e:
                p = subprocess.Popen("ls | grep -P -v \"zip$|repro$\" | xargs -d\"\\n\" rm -rf", shell=True)
                p.communicate()
                continue
            os.mkdir(repro_dir)
            #subprocess.Popen(['unzip', zip_repro])
            prepare_all_cmd_for_ctu.prepare(pathOptions)
            compile_cmd = json.load(open('./compile_cmd_DEBUG.json'))
            # uniquing stuff
            compile_cmd = {x['command']: x for x in compile_cmd}.values()
            #compile_cmd = list(np.unique(np.array(compile_cmd)))
            for x in compile_cmd:
                if not (str(x['file']).endswith('.c') or str(x['file']).endswith('.cpp')):
                    continue
                file_name = os.path.basename(x['file'].decode("utf-8"))
                preproc = subprocess.Popen(get_preprocess_cmd(x['command'], repro_dir, file_name),
                                           cwd=x['directory'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, err = preproc.communicate()
                x['directory'] = repro_dir
                x['file'] = os.path.join(repro_dir, file_name)
                x['command'] = get_new_cmd(x['command'], repro_dir)
            # with open(x['file'], 'w') as f:
            #    f.write(out)
            # uniquing stuff
            compile_cmd = {x['command']: x for x in compile_cmd}.values()
            with open(os.path.join(repro_dir, 'compile_commands.json'),'w') as out_cc:
                out_cc.write(json.dumps(compile_cmd,indent=4))

            with open(args.analyzer_command, 'r') as f:
                with open(analyzer_command_file,'w') as f2:
                    f2.write(get_new_analyzer_cmd(f.read(), repro_dir))

            print repro_dir
        else:
            compile_cmd = json.load(open(os.path.join(repro_dir, './compile_commands.json')))

        os.chdir(repro_dir)
        out = prepare_all_cmd_for_ctu.execute(["CodeChecker", "analyze", "--ctu-collect",
               "compile_commands.json",
               "-o", "cc_files",
               "--verbose", "debug"])

        print repro_dir   


        assert_string = get_assertion_string(analyzer_command_file)
        if assert_string in assert_string_set:
            os.chdir(args.fail_dir)
            print "DELETEEEEEEEEEEE"
            p = subprocess.Popen("ls | grep -P -v \"zip$|repro$\" | xargs -d\"\\n\" rm -rf", shell=True)
            shutil.rmtree(repro_dir)
            p.communicate()
            continue

        assert_string_set.add(assert_string)
        print assert_string
        abs_file_path = get_file_path(analyzer_command_file)
        print abs_file_path
        with open(analyzer_command_file, 'r') as f:
            std_flag = get_std_flag(f.read())
        #preproc_name = get_preprocessed_repro_file(abs_file_path, analyzer_command_file)
        reduced_file_name = reduce(abs_file_path, assert_string, analyzer_command_file, args.j, std_flag)
        print reduced_file_name
        

        #prepare_all_cmd_for_ctu.prepare(pathOptions)
        cmd_to_remove = set()
        for x in compile_cmd:
            if not (x['file'].endswith('.c') or x['file'].endswith('.cpp')) or (os.path.basename(x['file']) == reduced_file_name):
                continue
            std_flag = get_std_flag(x['command'])
            reduce_dep(x['file'], assert_string, analyzer_command_file, reduced_file_name, std_flag)

            if os.stat(x['file']).st_size == 0:
                os.remove(x['file'])
                cmd_to_remove.add(x['command'])
            else:
                out = prepare_all_cmd_for_ctu.execute(["CodeChecker", "analyze", "--ctu-collect",
                                                       "compile_commands.json",
                                                       "-o", "cc_files",
                                                       "--verbose", "debug"])

        compile_cmd = [x for x in compile_cmd if x['command'] not in cmd_to_remove]
        with open(os.path.join(repro_dir, 'compile_commands.json'),'w') as out_cc:
            out_cc.write(json.dumps(compile_cmd, indent=4))
            #print get_preprocess_cmd(x['command'])
            #out, err = preproc.communicate()
            #print err + " :Err, Out:" + out
            #print x['command']
        os.chdir(args.fail_dir)
        print "DELETEEEEEEEEEEE"
        p = subprocess.Popen("ls | grep -P -v \"zip$|repro$\" | xargs -d\"\\n\" rm -rf", shell=True)
        p.communicate()
if __name__ == '__main__':
    main()
