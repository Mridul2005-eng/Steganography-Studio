import base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import cv2

from steganography_core import (
    CapacityError,
    SteganographyError,
    decode_image,
    encode_image,
    estimate_payload_size,
    get_image_capacity,
)


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Studio")
        self.root.geometry("760x520")
        self.root.minsize(680, 480)

        self.encode_image_path = tk.StringVar()
        self.encode_output_path = tk.StringVar(value="encryptedImage.png")
        self.encode_password = tk.StringVar()
        self.capacity_var = tk.StringVar(value="Select an image, then enter a message and password.")
        self.encode_show_password = tk.BooleanVar(value=False)

        self.decode_image_path = tk.StringVar(value="encryptedImage.png")
        self.decode_password = tk.StringVar()
        self.decode_show_password = tk.BooleanVar(value=False)

        self.status_var = tk.StringVar(value="Ready.")
        self.preview_image = None

        self.build_ui()
        self.attach_live_updates()

    def build_ui(self):
        container = ttk.Frame(self.root, padding=16)
        container.pack(fill="both", expand=True)

        title = ttk.Label(
            container,
            text="Image Steganography Toolkit",
            font=("Segoe UI", 18, "bold"),
        )
        title.pack(anchor="w")

        subtitle = ttk.Label(
            container,
            text="Hide encrypted messages inside PNG output images and recover them with the correct password.",
        )
        subtitle.pack(anchor="w", pady=(4, 12))

        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True)

        encode_tab = ttk.Frame(notebook, padding=16)
        decode_tab = ttk.Frame(notebook, padding=16)
        notebook.add(encode_tab, text="Encode")
        notebook.add(decode_tab, text="Decode")

        self.build_encode_tab(encode_tab)
        self.build_decode_tab(decode_tab)

        status = ttk.Label(container, textvariable=self.status_var, foreground="#1b4d3e")
        status.pack(anchor="w", pady=(12, 0))

    def build_encode_tab(self, parent):
        ttk.Label(parent, text="Cover image").grid(row=0, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.encode_image_path, width=72).grid(
            row=1, column=0, sticky="ew", padx=(0, 8)
        )
        ttk.Button(parent, text="Browse", command=self.browse_encode_image).grid(row=1, column=1)

        ttk.Label(parent, text="Output image").grid(row=2, column=0, sticky="w", pady=(12, 0))
        ttk.Entry(parent, textvariable=self.encode_output_path, width=72).grid(
            row=3, column=0, sticky="ew", padx=(0, 8)
        )
        ttk.Button(parent, text="Save As", command=self.browse_output_image).grid(row=3, column=1)

        ttk.Label(parent, text="Password").grid(row=4, column=0, sticky="w", pady=(12, 0))
        ttk.Entry(parent, textvariable=self.encode_password, width=40, show="*").grid(
            row=5, column=0, sticky="w"
        )
        self.encode_password_entry = parent.grid_slaves(row=5, column=0)[0]
        ttk.Checkbutton(
            parent,
            text="Show password",
            variable=self.encode_show_password,
            command=self.toggle_encode_password,
        ).grid(row=5, column=1, sticky="w")

        ttk.Label(parent, text="Secret message").grid(row=6, column=0, sticky="w", pady=(12, 0))
        self.encode_message = tk.Text(parent, height=10, wrap="word")
        self.encode_message.grid(row=7, column=0, columnspan=2, sticky="nsew")

        info = ttk.Label(
            parent,
            text="Tip: save encoded images as PNG so the hidden bits are preserved.",
            foreground="#555555",
        )
        info.grid(row=8, column=0, columnspan=2, sticky="w", pady=(10, 0))

        capacity_label = ttk.Label(
            parent,
            textvariable=self.capacity_var,
            justify="left",
        )
        capacity_label.grid(row=9, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self.capacity_label = capacity_label

        ttk.Button(parent, text="Encode Message", command=self.run_encode).grid(
            row=10, column=0, sticky="w", pady=(16, 0)
        )

        self.preview_label = ttk.Label(parent, text="Image preview will appear here.")
        self.preview_label.grid(row=0, column=2, rowspan=11, sticky="n", padx=(18, 0))

        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(7, weight=1)

    def build_decode_tab(self, parent):
        ttk.Label(parent, text="Encoded image").grid(row=0, column=0, sticky="w")
        ttk.Entry(parent, textvariable=self.decode_image_path, width=72).grid(
            row=1, column=0, sticky="ew", padx=(0, 8)
        )
        ttk.Button(parent, text="Browse", command=self.browse_decode_image).grid(row=1, column=1)

        ttk.Label(parent, text="Password").grid(row=2, column=0, sticky="w", pady=(12, 0))
        ttk.Entry(parent, textvariable=self.decode_password, width=40, show="*").grid(
            row=3, column=0, sticky="w"
        )
        self.decode_password_entry = parent.grid_slaves(row=3, column=0)[0]
        ttk.Checkbutton(
            parent,
            text="Show password",
            variable=self.decode_show_password,
            command=self.toggle_decode_password,
        ).grid(row=3, column=1, sticky="w")

        ttk.Label(parent, text="Recovered message").grid(row=4, column=0, sticky="w", pady=(12, 0))
        self.decode_message = tk.Text(parent, height=12, wrap="word")
        self.decode_message.grid(row=5, column=0, columnspan=2, sticky="nsew")

        ttk.Button(parent, text="Decode Message", command=self.run_decode).grid(
            row=6, column=0, sticky="w", pady=(16, 0)
        )
        ttk.Button(parent, text="Copy Message", command=self.copy_decoded_message).grid(
            row=6, column=1, sticky="w", pady=(16, 0)
        )

        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(5, weight=1)

    def browse_encode_image(self):
        path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png *.bmp *.jpg *.jpeg"), ("All files", "*.*")]
        )
        if path:
            self.encode_image_path.set(path)
            self.update_image_preview(path)

    def browse_output_image(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG image", "*.png"), ("Bitmap image", "*.bmp")],
        )
        if path:
            self.encode_output_path.set(path)

    def browse_decode_image(self):
        path = filedialog.askopenfilename(
            filetypes=[("Image files", "*.png *.bmp"), ("All files", "*.*")]
        )
        if path:
            self.decode_image_path.set(path)

    def attach_live_updates(self):
        self.encode_image_path.trace_add("write", self.refresh_capacity_status)
        self.encode_image_path.trace_add("write", self.refresh_preview_from_trace)
        self.encode_password.trace_add("write", self.refresh_capacity_status)
        self.encode_message.bind("<KeyRelease>", self.refresh_capacity_status)

    def refresh_preview_from_trace(self, *_args):
        path = self.encode_image_path.get().strip()
        if path:
            self.update_image_preview(path)
        else:
            self.preview_label.configure(image="", text="Image preview will appear here.")
            self.preview_image = None

    def update_image_preview(self, image_path):
        try:
            image = get_image_preview(image_path, max_size=220)
        except SteganographyError as exc:
            self.preview_label.configure(image="", text=f"Preview unavailable:\n{exc}")
            self.preview_image = None
            return

        self.preview_image = image
        self.preview_label.configure(image=self.preview_image, text="")

    def toggle_encode_password(self):
        self.encode_password_entry.configure(show="" if self.encode_show_password.get() else "*")

    def toggle_decode_password(self):
        self.decode_password_entry.configure(show="" if self.decode_show_password.get() else "*")

    def copy_decoded_message(self):
        message = self.decode_message.get("1.0", "end").strip()
        if not message:
            messagebox.showwarning("Nothing to Copy", "There is no decoded message to copy yet.")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(message)
        self.status_var.set("Decoded message copied to clipboard.")

    def refresh_capacity_status(self, *_args):
        image_path = self.encode_image_path.get().strip()
        message = self.encode_message.get("1.0", "end").strip()
        password = self.encode_password.get()

        if not image_path:
            self.capacity_var.set("Select an image, then enter a message and password.")
            self.capacity_label.configure(foreground="#1f3a5f")
            return

        try:
            capacity = get_image_capacity(image_path)
        except SteganographyError as exc:
            self.capacity_var.set(f"Image error: {exc}")
            self.capacity_label.configure(foreground="#a12626")
            return

        if not message or not password:
            self.capacity_var.set(
                f"Image capacity: {capacity} bytes. Enter both message and password to estimate usage."
            )
            self.capacity_label.configure(foreground="#1f3a5f")
            return

        try:
            payload_size = estimate_payload_size(message, password)
        except SteganographyError as exc:
            self.capacity_var.set(str(exc))
            self.capacity_label.configure(foreground="#a12626")
            return

        remaining = capacity - payload_size
        fits_text = "Yes" if remaining >= 0 else "No"
        color = "#1b6e3c" if remaining >= 0 else "#a12626"
        self.capacity_var.set(
            f"Image capacity: {capacity} bytes | Estimated payload: {payload_size} bytes | "
            f"Fits: {fits_text} | Remaining: {remaining} bytes"
        )
        self.capacity_label.configure(foreground=color)

    def run_encode(self):
        message = self.encode_message.get("1.0", "end").strip()
        try:
            result = encode_image(
                self.encode_image_path.get().strip(),
                self.encode_output_path.get().strip(),
                message,
                self.encode_password.get(),
            )
        except CapacityError as exc:
            messagebox.showwarning("Image Capacity", str(exc))
            self.status_var.set("Encoding stopped: image capacity is too small.")
            return
        except SteganographyError as exc:
            messagebox.showerror("Encode Failed", str(exc))
            self.status_var.set("Encoding failed.")
            return

        self.status_var.set(
            f"Message encoded successfully. Payload: {result['payload_bytes']} bytes."
        )
        messagebox.showinfo(
            "Encode Complete",
            f"Message saved to:\n{result['output_path']}\n\n"
            f"Payload bytes used: {result['payload_bytes']}\n"
            f"Image capacity bytes: {result['image_capacity_bytes']}",
        )
        self.refresh_capacity_status()

    def run_decode(self):
        self.decode_message.delete("1.0", "end")
        try:
            result = decode_image(
                self.decode_image_path.get().strip(),
                self.decode_password.get(),
            )
        except SteganographyError as exc:
            messagebox.showerror("Decode Failed", str(exc))
            self.status_var.set("Decoding failed.")
            return

        self.decode_message.insert("1.0", result["message"])
        self.status_var.set(
            f"Message decoded successfully. Payload: {result['payload_bytes']} bytes."
        )


def get_image_preview(image_path, max_size=220):
    image = cv2.imread(image_path)
    if image is None:
        raise SteganographyError(f"Unable to read image: {image_path}")

    height, width = image.shape[:2]
    scale = min(max_size / width, max_size / height, 1)
    preview = cv2.resize(image, (int(width * scale), int(height * scale)))
    preview = cv2.cvtColor(preview, cv2.COLOR_BGR2RGB)

    success, encoded = cv2.imencode(".png", cv2.cvtColor(preview, cv2.COLOR_RGB2BGR))
    if not success:
        raise SteganographyError("Unable to create image preview.")

    data = base64.b64encode(encoded.tobytes()).decode("ascii")
    return tk.PhotoImage(data=data)


if __name__ == "__main__":
    root = tk.Tk()
    app = SteganographyApp(root)
    root.mainloop()
