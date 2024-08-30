import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import os
import ast
import pyperclip
import json

class CodePreparationTool:
    def __init__(self, root):
        self.root = root
        self.root.title("Code Preparation Tool for LLM")
        self.root.geometry("1200x800")

        self.file_strategies = {}
        self.function_strategies = {}
        self.file_frames = {}  # Add this line to initialize file_frames
        self.selected_file = None
        self.project_directory = None
        self.create_widgets()
        self.aggregated_code = ""
        self.load_options()

    def create_widgets(self):
        self.main_frame = tk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.left_frame = tk.Frame(self.main_frame, width=500)
        self.right_frame = tk.Frame(self.main_frame, width=500)
        self.output_frame = tk.Frame(self.main_frame, width=300)

        self.main_frame.paneconfigure(self.left_frame, minsize=500)
        self.main_frame.paneconfigure(self.right_frame, minsize=500)
        self.main_frame.paneconfigure(self.output_frame, minsize=300)

        self.main_frame.add(self.left_frame)
        self.main_frame.add(self.right_frame)
        self.main_frame.add(self.output_frame)

        # Left Panel (Files)
        self.create_file_panel()

        # Right Panel (Functions)
        self.create_function_panel()

        # Output Panel
        self.create_output_panel()

        # Bottom Panel
        self.create_bottom_panel()

    def create_file_panel(self):
        self.file_frame = tk.Frame(self.left_frame)
        self.file_frame.pack(fill=tk.BOTH, expand=True)

        self.file_canvas = tk.Canvas(self.file_frame)
        self.file_scrollbar = tk.Scrollbar(self.file_frame, orient="vertical", command=self.file_canvas.yview)
        self.scrollable_file_frame = tk.Frame(self.file_canvas, bg="white")  # Set white background

        self.scrollable_file_frame.bind(
            "<Configure>",
            lambda e: self.file_canvas.configure(
                scrollregion=self.file_canvas.bbox("all")
            )
        )

        self.file_canvas.create_window((0, 0), window=self.scrollable_file_frame, anchor="nw")
        self.file_canvas.configure(yscrollcommand=self.file_scrollbar.set)

        self.file_canvas.pack(side="left", fill="both", expand=True)
        self.file_scrollbar.pack(side="right", fill="y")

        # File panel header
        header_frame = tk.Frame(self.scrollable_file_frame, bg="white")  # Set white background
        header_frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(header_frame, text="File", width=40, anchor="w", bg="white").pack(side=tk.LEFT)
        tk.Label(header_frame, text="Strategy", width=30, bg="white").pack(side=tk.LEFT)

    def create_function_panel(self):
        self.function_frame = tk.Frame(self.right_frame)
        self.function_frame.pack(fill=tk.BOTH, expand=True)

        self.function_canvas = tk.Canvas(self.function_frame)
        self.function_scrollbar = tk.Scrollbar(self.function_frame, orient="vertical", command=self.function_canvas.yview)
        self.scrollable_function_frame = tk.Frame(self.function_canvas)

        self.scrollable_function_frame.bind(
            "<Configure>",
            lambda e: self.function_canvas.configure(
                scrollregion=self.function_canvas.bbox("all")
            )
        )

        self.function_canvas.create_window((0, 0), window=self.scrollable_function_frame, anchor="nw")
        self.function_canvas.configure(yscrollcommand=self.function_scrollbar.set)

        self.function_canvas.pack(side="left", fill="both", expand=True)
        self.function_scrollbar.pack(side="right", fill="y")

        # Function panel header
        header_frame = tk.Frame(self.scrollable_function_frame)
        header_frame.pack(fill=tk.X, padx=5, pady=2)
        tk.Label(header_frame, text="Function", width=30, anchor="w").pack(side=tk.LEFT)
        tk.Label(header_frame, text="Strategy", width=15).pack(side=tk.LEFT)

    def create_output_panel(self):
        output_frame = tk.Frame(self.output_frame)
        output_frame.pack(fill=tk.BOTH, expand=True)

        self.output_text = tk.Text(output_frame, wrap=tk.WORD)
        output_scrollbar = tk.Scrollbar(output_frame, orient="vertical", command=self.output_text.yview)

        self.output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        output_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.output_text.configure(yscrollcommand=output_scrollbar.set)

    def create_bottom_panel(self):
        self.button_frame = tk.Frame(self.root)
        self.button_frame.pack(fill=tk.X, side=tk.BOTTOM)

        self.browse_button = tk.Button(self.button_frame, text="Browse", command=self.browse_directory)
        self.browse_button.pack(side=tk.LEFT)

        self.refresh_button = tk.Button(self.button_frame, text="Refresh", command=self.refresh_directory)
        self.refresh_button.pack(side=tk.LEFT)

        self.process_button = tk.Button(self.button_frame, text="Process All", command=self.process_all_files)
        self.process_button.pack(side=tk.LEFT)

        self.save_button = tk.Button(self.button_frame, text="Save to File", command=self.save_to_file)
        self.save_button.pack(side=tk.LEFT)

        self.copy_button = tk.Button(self.button_frame, text="Copy to Clipboard", command=self.copy_to_clipboard)
        self.copy_button.pack(side=tk.LEFT)

        self.comment_toggle = tk.IntVar()
        self.comment_check = tk.Checkbutton(self.button_frame, text="Remove Comments", variable=self.comment_toggle)
        self.comment_check.pack(side=tk.RIGHT)

    def browse_directory(self):
        directory = filedialog.askdirectory()
        if directory:
            self.project_directory = directory
            self.load_files(directory)
            self.save_options()

    def load_files(self, directory):
        for widget in self.scrollable_file_frame.winfo_children():
            if isinstance(widget, tk.Frame) and widget.winfo_children()[0].cget("text") != "File":
                widget.destroy()

        self.file_frames.clear()  # Clear the file_frames dictionary

        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith(".py"):
                    file_path = os.path.join(root, file)
                    self.add_file_widget(file_path)

    def add_file_widget(self, file_path):
        file_frame = tk.Frame(self.scrollable_file_frame, bg="white")
        file_frame.pack(fill=tk.X, padx=5, pady=2)

        file_label = tk.Label(file_frame, text=os.path.basename(file_path), width=30, anchor="w", bg="white")
        file_label.pack(side=tk.LEFT)

        if file_path not in self.file_strategies:
            self.file_strategies[file_path] = tk.StringVar(value="Include Full File")
        file_strategy = self.file_strategies[file_path]

        file_dropdown = ttk.Combobox(file_frame, textvariable=file_strategy, width=40)
        file_dropdown['values'] = (
            "Include Full File", "Exclude File", "Include Function Names and Return Values", "Include Docstrings Only")
        file_dropdown.pack(side=tk.LEFT)

        file_dropdown.bind("<<ComboboxSelected>>", lambda e: self.update_function_options(file_path))

        file_label.bind("<Button-1>", lambda e, fp=file_path: self.load_functions(fp))
        file_frame.bind("<Button-1>", lambda e, fp=file_path: self.load_functions(fp))

        self.file_frames[file_path] = file_frame

    def update_function_options(self, file_path):
        file_option = self.file_strategies[file_path].get()
        function_option = {
            "Include Full File": "Include Full Function",
            "Exclude File": "Exclude Function",
            "Include Function Names and Return Values": "Include Signature Only",
            "Include Docstrings Only": "Include Docstrings Only"
        }.get(file_option, "Include Full Function")

        for key in list(self.function_strategies.keys()):
            if key[0] == file_path:
                self.function_strategies[key].set(function_option)

        # Refresh the function panel if it's currently showing this file
        if self.selected_file == file_path:
            self.load_functions(file_path)

    def add_function_widget(self, file_path, func_name):
        func_frame = tk.Frame(self.scrollable_function_frame)
        func_frame.pack(fill=tk.X, padx=5, pady=2)

        func_label = tk.Label(func_frame, text=func_name, width=30, anchor="w")
        func_label.pack(side=tk.LEFT)

        if (file_path, func_name) not in self.function_strategies:
            self.function_strategies[(file_path, func_name)] = tk.StringVar(value="Include Full Function")
        func_strategy = self.function_strategies[(file_path, func_name)]

        func_dropdown = ttk.Combobox(func_frame, textvariable=func_strategy, width=30)
        func_dropdown['values'] = (
        "Include Full Function", "Exclude Function", "Include Signature Only", "Include Return Values Only",
        "Include Docstrings Only")
        func_dropdown.pack(side=tk.LEFT)



    def process_all_files(self):
        self.aggregated_code = ""
        for file_path in self.file_strategies.keys():
            self.process_file(file_path)
        self.output_text.delete('1.0', tk.END)
        self.output_text.insert(tk.END, self.aggregated_code)
        self.save_options()

    def process_file(self, file_path):
        with open(file_path, "r") as file:
            code = file.read()
            if self.comment_toggle.get():
                code = self.remove_comments(code)
            tree = ast.parse(code)

            file_option = self.file_strategies[file_path].get()
            if file_option == "Exclude File":
                return

            self.aggregated_code += f"```python\n# File: {file_path}\n"

            if file_option == "Include Full File":
                self.aggregated_code += code + "\n"
            else:
                self.process_non_function_code(tree, code)
                for node in ast.iter_child_nodes(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        function_option = self.function_strategies.get((file_path, node.name), tk.StringVar()).get()
                        self.process_function(file_path, node, code, function_option)

            self.aggregated_code += "```\n\n"

    def process_non_function_code(self, tree, code):
        for node in ast.iter_child_nodes(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.aggregated_code += ast.get_source_segment(code, node) + "\n"
        self.aggregated_code += "\n"

    def process_function(self, file_path, func, code, function_option):
        if function_option == "Exclude Function":
            return

        func_sig = f"{'async ' if isinstance(func, ast.AsyncFunctionDef) else ''}def {func.name}({ast.unparse(func.args)}):"
        docstring = ast.get_docstring(func)

        if function_option == "Include Full Function":
            self.aggregated_code += f"{ast.get_source_segment(code, func)}\n\n"
        elif function_option == "Include Signature Only":
            self.aggregated_code += f"{func_sig}\n    pass\n\n"
        elif function_option == "Include Return Values Only":
            return_stmt = next((ast.unparse(node.value) for node in ast.walk(func) if isinstance(node, ast.Return)),
                               None)
            self.aggregated_code += f"{func_sig}\n    return {return_stmt if return_stmt else 'None'}\n\n"
        elif function_option == "Include Docstrings Only":
            if docstring:
                self.aggregated_code += f"{func_sig}\n    \"\"\"\n    {docstring}\n    \"\"\"\n    pass\n\n"
            else:
                self.aggregated_code += f"{func_sig}\n    pass\n\n"

    def load_functions(self, file_path):
        for selected_file, file_frame in self.file_frames.items():
            if selected_file == file_path:
                file_frame.configure(bg="lightblue")
            else:
                file_frame.configure(bg="white")

        self.selected_file = file_path

        for widget in self.scrollable_function_frame.winfo_children():
            if isinstance(widget, tk.Frame) and widget.winfo_children()[0].cget("text") != "Function":
                widget.destroy()

        with open(file_path, "r") as file:
            code = file.read()
            tree = ast.parse(code)
            functions = [node for node in ast.iter_child_nodes(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]

            for func in functions:
                self.add_function_widget(file_path, func.name)

    def remove_comments(self, code):
        lines = code.split("\n")
        stripped_lines = []
        for line in lines:
            if not line.strip().startswith("#"):
                stripped_lines.append(line)
        return "\n".join(stripped_lines)

    def save_to_file(self):
        output_path = filedialog.asksaveasfilename(defaultextension=".md", filetypes=[("Markdown Files", "*.md")])
        if output_path:
            with open(output_path, "w") as output_file:
                output_file.write(self.aggregated_code)
            messagebox.showinfo("Success", f"Output saved to {output_path}")

    def copy_to_clipboard(self):
        pyperclip.copy(self.aggregated_code)
        messagebox.showinfo("Success", "Output copied to clipboard")

    def refresh_directory(self):
        if self.project_directory:
            self.load_files(self.project_directory)

    def save_options(self):
        options = {
            "project_directory": self.project_directory,
            "file_strategies": {k: v.get() for k, v in self.file_strategies.items()},
            "function_strategies": {f"{k[0]}:{k[1]}": v.get() for k, v in self.function_strategies.items()},
            "comment_toggle": self.comment_toggle.get()
        }
        with open("options.json", "w") as f:
            json.dump(options, f)

    def load_options(self):
        try:
            with open("options.json", "r") as f:
                options = json.load(f)
            self.project_directory = options.get("project_directory")
            self.file_strategies = {k: tk.StringVar(value=v) for k, v in options.get("file_strategies", {}).items()}
            self.function_strategies = {tuple(k.split(":")): tk.StringVar(value=v) for k, v in options.get("function_strategies", {}).items()}
            self.comment_toggle.set(options.get("comment_toggle", 0))
            if self.project_directory:
                self.load_files(self.project_directory)
        except FileNotFoundError:
            pass

if __name__ == "__main__":
    root = tk.Tk()
    app = CodePreparationTool(root)
    root.mainloop()