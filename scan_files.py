#!/usr/bin/env python3
"""全量雷达扫描：把项目内文本代码与图片路径合并输出为单个文件（便于整库审查/喂给分析）。"""

import os


def scan_and_merge():
    # 1. 路径设置：脚本所在目录即为扫描根（当前 = ApkSignatureKillerEx）
    base_dir = os.path.dirname(os.path.abspath(__file__))
    target_root = os.path.normpath(os.path.join(base_dir, "."))
    output_file = os.path.join(base_dir, "merged_ApkKiller.txt")

    # 2. 规则
    text_extensions = {'.js', '.kt', '.java', '.xml', '.gradle', '.md',
                       '.pro', '.cpp', '.h', '.proto', '.properties', '.yml', '.c', '.py'}
    image_extensions = {'.png', '.jpg', '.jpeg', '.webp', '.ico'}

    # 忽略编译/依赖目录
    ignore_dirs = {'.gradle', '.idea', 'build', 'bin', 'gen', 'out', 'gradle', '__pycache__'}

    if not os.path.exists(target_root):
        print(f"错误: 找不到目录 {target_root}")
        return

    print(f"正在全量雷达扫描: {target_root}")
    print(f"结果将保存至: {output_file}")

    with open(output_file, 'w', encoding='utf-8') as f_out:
        for root, dirs, files in os.walk(target_root):
            dirs[:] = [d for d in dirs if d not in ignore_dirs]

            rel_dir = os.path.relpath(root, target_root)

            for file in files:
                file_path = os.path.join(root, file)
                # 相对项目根显示，避免 ../../ 前缀
                display_path = os.path.relpath(file_path, target_root)
                ext = os.path.splitext(file)[1].lower()

                if ext in text_extensions:
                    f_out.write("\n" + "=" * 60 + "\n")
                    f_out.write(f"【文本文件内容】路径: {display_path}\n")
                    f_out.write("=" * 60 + "\n\n")
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f_in:
                            f_out.write(f_in.read())
                    except Exception as e:
                        f_out.write(f"[读取失败: {str(e)}]\n")
                    f_out.write("\n\n")
                elif ext in image_extensions:
                    f_out.write(f"\n【图片文件路径】: {display_path}\n")

    print("扫描完成")


if __name__ == "__main__":
    scan_and_merge()
