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


def reduce(prepoc_name, assert_string, analyzer_command_file, num_threads):
    reduce_file_name = prepoc_name.replace("preproc", "reduce")
    if not os.path.exists(reduce_file_name):
        shutil.copy2(prepoc_name, reduce_file_name)
    else:
        return reduce_file_name
    conditions = []
    compilable_cond = ['gcc', '-c', '-Werror', reduce_file_name]
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
    conditions.append(' '.join(ctu_analyze_fail_cond))

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


def reduce_dep(dep_file_abs_path, assert_string, analyzer_command_file, reduced_orig_file_name):
    reduce_file_name = os.path.basename(dep_file_abs_path)
    print dep_file_abs_path
    ast_dump_path = os.path.join(os.path.abspath('./report_debug'), 'ctu-dir', 'x86_64', 'ast')
    #print ast_dump_path
    ast_dump_path = os.path.join(ast_dump_path, '.' + dep_file_abs_path + '.ast')
    #print ast_dump_path
    #return
    conditions = []
    compilable_cond = ['gcc', '-c', '-Werror', reduce_file_name]
    conditions.append(' '.join(compilable_cond))
    ast_dump_cond = ['clang', '-cc1', '-emit-pch', '-o', ast_dump_path, reduce_file_name]
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


def get_preprocess_cmd(comp_cmd):
    preproc_cmd = str(comp_cmd.decode("utf-8")).split(' ')
    preproc_cmd = filter(lambda x: not re.match('-c', x), preproc_cmd)
    preproc_cmd.insert(1, '-E')
    out_ind = preproc_cmd.index('-o')
    del preproc_cmd[out_ind]
    del preproc_cmd[out_ind]
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
        '--clang',
        required=True,
        help="Path to the clang binary.")
    parser.add_argument(
        '--clang_plugin_name', default=None,
        help="Name of the used clang plugin.")
    parser.add_argument(
        '--clang_plugin_path', default=None,
        help="Path to the used clang plugin.")
    args = parser.parse_args()
    # change the paths to absolute
    args.sources_root = os.path.abspath(args.sources_root)
    pathOptions = prepare_all_cmd_for_ctu.PathOptions(
            args.sources_root,
            args.clang,
            args.clang_plugin_name,
            args.clang_plugin_path,
            args.report_dir)

    prepare_all_cmd_for_ctu.prepare(pathOptions)
    assert_string = get_assertion_string(args.analyzer_command)
    abs_file_path = get_file_path(args.analyzer_command)
    preproc_name = get_preprocessed_repro_file(abs_file_path, args.analyzer_command)
    reduced_orig_file_name = reduce(preproc_name, assert_string, args.analyzer_command, args.j)
    compile_cmd = json.load(open('./report_debug/compile_cmd.json'))

    out = prepare_all_cmd_for_ctu.execute(["CodeChecker", "analyze", "--ctu-collect",
                   compile_cmd_debug,
                   "--compiler-includes-file", compiler_includes_debug,
                   "--compiler-target-file", compiler_target_debug,
                   "-o", "report_debug",
                   "--verbose", "debug"])

    for x in compile_cmd:
        if not (str(x['file']).endswith('.c') or str(x['file']).endswith('.cpp')):
            continue
        preproc = subprocess.Popen(get_preprocess_cmd(x['command']),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = preproc.communicate()
        with open(x['file'], 'w') as f:
            f.write(out)
    prepare_all_cmd_for_ctu.prepare(pathOptions)
    for x in compile_cmd:
        if not (str(x['file']).endswith('.c') or str(x['file']).endswith('.cpp')):
            continue
        reduce_dep(str(x['file']), assert_string, args.analyzer_command, reduced_orig_file_name)

        if os.stat(str(x['file'])).st_size != 0:
            prepare_all_cmd_for_ctu.prepare(pathOptions)

        #print get_preprocess_cmd(x['command'])
        #out, err = preproc.communicate()
        #print err + " :Err, Out:" + out
        #print x['command']


if __name__ == '__main__':
    main()
