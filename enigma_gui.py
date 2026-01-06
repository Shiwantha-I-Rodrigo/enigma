import tkinter as tk
from tkinter import ttk, messagebox
from PIL import Image, ImageTk
from pathlib import Path

# ------------------ App Window ------------------
root = tk.Tk()
root.title("Enigma GUI")
root.geometry("335x650")
root.resizable(False, False)
root.configure(bg="#0D0208")

# ------------------ Styles ------------------
bg = "#0D0208"
fg = "#008F11"

style = ttk.Style()
style.configure(
    "Custom.TButton",
    background=bg,
    foreground=fg,
)
style.configure(
    "Custom.TLabel",
    background=bg,
    foreground=fg,
)
style.configure(
    "My.TFrame",
    background=bg,
)
style.configure(
    "My.TEntry",
    foreground=fg,
    fieldbackground=bg,
    background=bg,
    insertcolor=fg,
)
style.map(
    "My.TEntry",
    fieldbackground=[
        ("readonly", fg),
    ],
    foreground=[
        ("readonly", bg),
    ],
)
style.configure(
    "Line.TSeparator",
    background=bg
)

# ------------------ Load & Resize Image ------------------
IMAGE_PATH = Path("logo.png")
image = Image.open(IMAGE_PATH)
image = image.resize((250, 250), Image.Resampling.LANCZOS)
photo = ImageTk.PhotoImage(image)

image_label = ttk.Label(root, image=photo, style="Custom.TLabel")
image_label.grid(row=0, column=0, columnspan=2, pady=20)

# ------------------ Input Fields ------------------
ttk.Label(root, text="Secret I:", style="Custom.TLabel").grid(row=2, column=0, sticky="w", padx=10, pady=5)
input1 = ttk.Entry(root, width=28, style="My.TEntry")
input1.grid(row=2, column=1, padx=10, pady=5)

ttk.Label(root, text="Secret II:", style="Custom.TLabel").grid(row=3, column=0, sticky="w", padx=10, pady=5)
input2 = ttk.Entry(root, width=28, style="My.TEntry")
input2.grid(row=3, column=1, padx=10, pady=5)

# ------------------ Output Fields ------------------
output2 = tk.Text( root, width=39, height=5, wrap="word", bg=fg, fg=bg, insertbackground=fg, bd=0, highlightthickness=0)
output2.config(state="disabled")
output2.grid(row=5, column=0, columnspan=2, padx=0, pady=5)

ttk.Label(root, text="Password:", style="Custom.TLabel").grid(row=6, column=0, sticky="e", padx=10, pady=5)
output1 = ttk.Entry(root, width=28, style="My.TEntry")
output1.grid(row=6, column=1, padx=10, pady=5)

# ------------------ Button Functions ------------------
def quick_pass():
    set_output1("quickpass123")
    multi_line_text = (
        f"First input: {input1.get()}\n"
        f"Second input: {input2.get()}\n"
        "Status: OK"
    )
    set_output2(multi_line_text)

def secure_pass():
    result = messagebox.askyesno("Confirm", "generating an extra secure password is slower than (around 1 min) and use atleast 4GB of memory, Do you want to continue?")
    if result:
        set_output1("secure_pass123")
        multi_line_text = (
        f"First input: {input1.get()}\n"
        f"Second input: {input2.get()}\n"
        "Status: OK"
        )
        set_output2(multi_line_text)
    else:
        pass

def test_strength():
    multi_line_text = (
        f"First input: {input1.get()}\n"
        f"Second input: {input2.get()}\n"
        "Status: OK"
    )
    set_output2(multi_line_text)

def bit_16():
    root.destroy()

def bit_128():
    root.destroy()

def copy():
    root.clipboard_clear()
    root.clipboard_append(output1.get())
    root.update() 

def clear():
    input1.delete(0, tk.END)
    input2.delete(0, tk.END)
    output1.config(state="normal")
    output2.config(state="normal")
    output1.delete(0, tk.END)
    output2.delete("1.0", tk.END)
    output1.config(state="normal")
    output2.config(state="disabled")

def two_factor():
    root.destroy()

def exit_app():
    root.destroy()

# ------------------ Sub Functions ------------------
def set_output1(text):
    output1.config(state="normal")
    output1.delete(0, tk.END)
    output1.insert(0, text)
    output1.config(state="readonly")

def set_output2(text):
    output2.config(state="normal")
    output2.delete("1.0", tk.END)
    output2.insert(tk.END, text)
    output2.config(state="disabled")

# ------------------ Buttons 1------------------
button_frame = ttk.Frame(root, style="My.TFrame")
button_frame.grid(row=7, column=0, columnspan=2, pady=20)

ttk.Button(button_frame, text="Quick Password", command=quick_pass, width=14, style="Custom.TButton").grid(row=0, column=0, padx=6)
ttk.Button(button_frame, text="Copy", command=copy, width=8, style="Custom.TButton").grid(row=0, column=1, padx=6)
ttk.Button(button_frame, text="Clear", command=clear, width=8, style="Custom.TButton").grid(row=0, column=2, padx=6)
ttk.Button(button_frame, text="Secure Password", command=secure_pass, width=14, style="Custom.TButton").grid(row=1, column=0, padx=6, pady=5)
ttk.Button(button_frame, text="16 Bit", command=bit_16, width=8, style="Custom.TButton").grid(row=1, column=1, padx=6, pady=5)
ttk.Button(button_frame, text="128 Bit", command=bit_128, width=8, style="Custom.TButton").grid(row=1, column=2, padx=6, pady=5)
ttk.Button(button_frame, text="Test Strength", command=test_strength, width=14, style="Custom.TButton").grid(row=2, column=0, padx=6)
ttk.Button(button_frame, text="2FA", command=two_factor, width=8, style="Custom.TButton").grid(row=2, column=1, padx=6)
ttk.Button(button_frame, text="Exit", command=exit_app, width=8, style="Custom.TButton").grid(row=2, column=2, padx=6)

# ------------------ Run ------------------
root.mainloop()
