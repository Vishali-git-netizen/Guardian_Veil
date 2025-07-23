# --- app2.py ---
import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from cryptography.fernet import Fernet
import os
import qrcode
import datetime
import serial
import time
import cv2
from face_auth import verify_face, capture_face_from_webcam
from pyzbar.pyzbar import decode
from hashlib import sha256

# --- Setup ---
key = Fernet.generate_key()
cipher = Fernet(key)

storage_path = "steganography_data"
os.makedirs(storage_path, exist_ok=True)

uploaded_image_label = None
decrypted_image_label = None
main_image_path = None


def hash_image(image_path):
    with open(image_path, "rb") as f:
        return sha256(f.read()).hexdigest()


def display_image(img_path, label):
    img = Image.open(img_path)
    img.thumbnail((300, 300))
    img = ImageTk.PhotoImage(img)
    label.config(image=img)
    label.image = img


def ask_password_and_image(callback):
    def submit_data():
        selected_file = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg")])
        if not selected_file:
            messagebox.showerror("Error", "Verification image is required.")
            return
        callback(password_entry.get(), selected_file)
        popup_window.destroy()

    popup_window = tk.Toplevel(root)
    popup_window.title("Enter Details")
    popup_window.geometry("400x250")
    popup_window.transient(root)

    tk.Label(popup_window, text="Enter Password:", font=("Arial", 12)).pack(pady=10)
    password_entry = tk.Entry(popup_window, show="*", width=30, font=("Arial", 12))
    password_entry.pack(pady=5)

    tk.Button(popup_window, text="Select Verification Image", command=submit_data, bg="#4CAF50", fg="white",
              font=("Arial", 12)).pack(pady=10)


def save_image_with_data():
    global uploaded_image_label, main_image_path

    main_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg")])
    if not main_image_path:
        return

    text_to_encrypt = text_entry.get("1.0", tk.END).strip()
    if not text_to_encrypt:
        messagebox.showerror("Error", "Text to encrypt is required.")
        return

    def process_save(password, verification_image_path):
        try:
            user_context = f"{text_to_encrypt} | Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            qr_img = qrcode.make(user_context)
            qr_path = "generated_qr.png"
            qr_img.save(qr_path)

            encrypted_text = cipher.encrypt(user_context.encode())
            verification_image_hash = hash_image(verification_image_path)

            main_save_path = os.path.join(storage_path, os.path.basename(main_image_path))
            img = Image.open(main_image_path)

            qr_img = Image.open(qr_path).resize((100, 100))
            img.paste(qr_img, (10, 10))
            img.save(main_save_path, "PNG")

            metadata_path = f"{main_save_path}.meta"
            with open(metadata_path, "wb") as f:
                f.write(password.encode() + b"\n")
                f.write(verification_image_hash.encode() + b"\n")
                f.write(encrypted_text)

            display_image(main_save_path, uploaded_image_label)
            messagebox.showinfo("Success", "Image saved with QR and encrypted data.")

        except Exception as e:
            messagebox.showerror("Error", f"Failed to save image: {e}")

    ask_password_and_image(process_save)


def decrypt_image():
    global decrypted_image_label, main_image_path

    main_image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg")])
    if not main_image_path:
        return

    def process_decrypt(password, verification_image_path):
        try:
            metadata_path = f"{main_image_path}.meta"
            if not os.path.exists(metadata_path):
                messagebox.showerror("Error", "No metadata found for the selected image.")
                return

            with open(metadata_path, "rb") as f:
                saved_password, verification_image_hash, encrypted_text = f.read().split(b"\n", 2)

            if password.encode() != saved_password:
                messagebox.showerror("Error", "Incorrect password.")
                return

            if hash_image(verification_image_path).encode() != verification_image_hash:
                messagebox.showerror("Error", "Verification image does not match.")
                return

            # ✅ Capture live image using webcam
            live_img_path = capture_face_from_webcam()
            if not live_img_path:
                messagebox.showwarning("Cancelled", "Live face capture cancelled.")
                return

            face_verified = verify_face(verification_image_path, live_img_path)
            if not face_verified:
                messagebox.showerror("Error", "Face authentication failed.")
                return

            decrypted_text = cipher.decrypt(encrypted_text).decode()
            messagebox.showinfo("Decrypted Text", f"Decrypted Message:\n\n{decrypted_text}")
            qr_result = decode_qr_from_image(main_image_path)
            messagebox.showinfo("QR Content", f"Decoded QR Message:\n\n{qr_result}")

            send_command_to_arduino("UNLOCK")
            time.sleep(5)
            send_command_to_arduino("LOCK")

            display_image(main_image_path, decrypted_image_label)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt image: {e}")

    ask_password_and_image(process_decrypt)


def send_command_to_arduino(command):
    try:
        arduino = serial.Serial('COM3', 9600, timeout=1)
        time.sleep(2)
        arduino.write((command + '\n').encode())
        arduino.close()
        print(f"Sent: {command}")
    except Exception as e:
        print(f"Arduino error: {e}")


def decode_qr_from_image(image_path):
    try:
        img = cv2.imread(image_path)
        decoded_objs = decode(img)
        return decoded_objs[0].data.decode("utf-8") if decoded_objs else "No QR code found."
    except Exception as e:
        return f"QR decode error: {e}"


# --- GUI Setup ---
root = tk.Tk()
root.title("Guardian Veil – Steganography with Face Authentication")
root.geometry("900x650")

bg_image = Image.open("background.jpg")
bg_image = bg_image.resize((900, 650), Image.Resampling.LANCZOS)
background_photo = ImageTk.PhotoImage(bg_image)
background_label = tk.Label(root, image=background_photo)
background_label.place(relwidth=1, relheight=1)

content_frame = tk.Frame(root, bg="white", padx=20, pady=20, relief="ridge", borderwidth=5)
content_frame.place(relx=0.5, rely=0.5, anchor="center")

tk.Label(content_frame, text="Text to Encrypt:", bg="white", font=("Arial", 14, "bold")).grid(row=0, column=0, padx=10, pady=5, sticky="ne")
text_entry = tk.Text(content_frame, height=5, width=40, font=("Arial", 12))
text_entry.grid(row=0, column=1, padx=10, pady=5)

save_button = tk.Button(content_frame, text="Save Image with Data", command=save_image_with_data, bg="#4CAF50", fg="white", font=("Arial", 12), width=20)
save_button.grid(row=1, column=0, columnspan=2, pady=10)

decrypt_button = tk.Button(content_frame, text="Decrypt Image", command=decrypt_image, bg="#2196F3", fg="white", font=("Arial", 12), width=20)
decrypt_button.grid(row=2, column=0, columnspan=2, pady=10)

uploaded_image_label = tk.Label(content_frame, text="Uploaded Image", bg="#f0f0f0", font=("Arial", 10), borderwidth=2, relief="groove")
uploaded_image_label.grid(row=3, column=0, padx=10, pady=10)

decrypted_image_label = tk.Label(content_frame, text="Decrypted Image", bg="#f0f0f0", font=("Arial", 10), borderwidth=2, relief="groove")
decrypted_image_label.grid(row=3, column=1, padx=10, pady=10)

root.mainloop()
