import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from PyPDF2 import PdfReader, PdfWriter
import os

class PDFSignerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PDF Signer App")
        self.root.geometry("400x600")  # Tamaño de ventana ajustado
        self.root.configure(bg="#f5f5f5")

        # Variables
        self.pdf_path = ""
        self.key_size = tk.IntVar(value=1024)  # Tamaño de clave por defecto a 1024 bits
        self.signature = None
        self.public_key = None

        # UI
        self.create_widgets()

    def create_widgets(self):
        title_label = tk.Label(self.root, text="PDF Signer", font=("Helvetica", 20), bg="#f5f5f5")
        title_label.pack(pady=10)

        # Botón para seleccionar PDF
        self.select_pdf_button = ttk.Button(self.root, text="Select PDF", command=self.select_pdf)
        self.select_pdf_button.pack(pady=10)

        # Mostrar ruta del PDF seleccionado
        self.pdf_label = tk.Label(self.root, text="No PDF selected", bg="#f5f5f5")
        self.pdf_label.pack(pady=5)

        # Opciones de tamaño de clave RSA
        size_frame = tk.LabelFrame(self.root, text="Select RSA Key Size", bg="#f5f5f5")
        size_frame.pack(pady=10, padx=10, fill="both")

        tk.Radiobutton(size_frame, text="1024 bits (Insecure)", variable=self.key_size, value=1024, bg="#f5f5f5").pack(anchor="w")
        tk.Radiobutton(size_frame, text="2048 bits (Secure)", variable=self.key_size, value=2048, bg="#f5f5f5").pack(anchor="w")

        # Botón para firmar el PDF
        self.sign_button = ttk.Button(self.root, text="Sign PDF", command=self.sign_pdf)
        self.sign_button.pack(pady=20)

        # Botón para verificar la firma
        self.verify_button = ttk.Button(self.root, text="Verify Signature", command=self.verify_signature)
        self.verify_button.pack(pady=10)
        self.verify_button.config(state=tk.DISABLED)  # Deshabilitar hasta que se firme un PDF

        # Botón para copiar valores
        self.copy_button = ttk.Button(self.root, text="Copy Key Values", command=self.copy_key_values)
        self.copy_button.pack(pady=10)
        self.copy_button.config(state=tk.DISABLED)  # Deshabilitar hasta que se firme un PDF

        # Mostrar información de clave y firma
        self.info_label = tk.Label(self.root, text="", bg="#f5f5f5", wraplength=380)  # Ajustar el ancho de la etiqueta
        self.info_label.pack(pady=20)

    def select_pdf(self):
        self.pdf_path = filedialog.askopenfilename(filetypes=[("PDF files", "*.pdf")])
        if self.pdf_path:
            self.pdf_label.config(text=os.path.basename(self.pdf_path))
        else:
            self.pdf_label.config(text="No PDF selected")

    def sign_pdf(self):
        if not self.pdf_path:
            messagebox.showerror("Error", "Please select a PDF first!")
            return

        # Generar clave RSA
        key_size = self.key_size.get()
        key = RSA.generate(key_size)
        self.public_key = key.publickey()  # Guardar clave pública
        self.signature = None  # Reiniciar la firma

        # Crear hash del contenido del PDF
        pdf_reader = PdfReader(self.pdf_path)
        pdf_writer = PdfWriter()
        for page_num in range(len(pdf_reader.pages)):
            pdf_writer.add_page(pdf_reader.pages[page_num])

        # Crear hash del PDF
        pdf_data = b""
        for page_num in range(len(pdf_reader.pages)):
            pdf_data += pdf_reader.pages[page_num].extract_text().encode('utf-8')

        hash_obj = SHA256.new(pdf_data)

        # Firmar el hash usando la clave privada
        self.signature = pkcs1_15.new(key).sign(hash_obj)

        # Guardar el PDF firmado
        output_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])
        if output_path:
            with open(output_path, "wb") as output_file:
                pdf_writer.write(output_file)
                messagebox.showinfo("Success", f"PDF signed and saved as {output_path}")
                self.verify_button.config(state=tk.NORMAL)  # Habilitar el botón de verificación
                self.copy_button.config(state=tk.NORMAL)  # Habilitar el botón de copiar

                # Mostrar valores de clave pública y firma
                self.display_key_and_signature(key)

        else:
            messagebox.showerror("Error", "Failed to save the signed PDF.")

    def display_key_and_signature(self, key):
        n = key.n  # Módulo de la clave pública
        e = key.e  # Exponente público
        s = int.from_bytes(self.signature, byteorder='big')  # Convertir la firma a un entero

        # Limitar la longitud de los valores mostrados a 30 caracteres
        n_display = str(n) if len(str(n)) <= 30 else str(n)[:30] + "..."
        e_display = str(e) if len(str(e)) <= 30 else str(e)[:30] + "..."
        s_display = str(s) if len(str(s)) <= 30 else str(s)[:30] + "..."

        info = f"Public Key (n): {n_display}\nPublic Exponent (e): {e_display}\nSignature (s): {s_display}"
        self.info_label.config(text=info)

    def copy_key_values(self):
        if self.signature and self.public_key:
            n = self.public_key.n
            e = self.public_key.e
            s = int.from_bytes(self.signature, byteorder='big')
            m = self.pdf_path  # Usar la ruta del PDF como el "m" (mensaje)

            values = f"n: {n}\ne: {e}\n"
            self.root.clipboard_clear()  # Limpiar el portapapeles
            self.root.clipboard_append(values)  # Copiar los valores al portapapeles
            messagebox.showinfo("Copied", "Key values copied to clipboard!")

    def verify_signature(self):
        if not self.pdf_path or not self.signature or not self.public_key:
            messagebox.showerror("Error", "Please sign a PDF first!")
            return

        pdf_reader = PdfReader(self.pdf_path)
        pdf_data = b""

        # Extraer texto de cada página para crear el hash
        for page_num in range(len(pdf_reader.pages)):
            pdf_data += pdf_reader.pages[page_num].extract_text().encode('utf-8')

        hash_obj = SHA256.new(pdf_data)

        # Verificar la firma
        try:
            pkcs1_15.new(self.public_key).verify(hash_obj, self.signature)
            messagebox.showinfo("Verification", "The signature is valid.")
        except (ValueError, TypeError):
            messagebox.showerror("Verification", "The signature is invalid.")

if __name__ == "__main__":
    root = tk.Tk()
    app = PDFSignerApp(root)
    root.mainloop()
