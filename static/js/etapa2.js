// Seletores de Elementos
const publicKeyUpload = document.getElementById("public-key-upload");
const fileUpload = document.getElementById("file-upload");
const fileInfo = document.getElementById("file-info");
const fileName = document.getElementById("file-name");
const fileSize = document.getElementById("file-size");
const fileHash = document.getElementById("file-hash");
const nextButton = document.getElementById("next-button");
const previousButton = document.getElementById("previous-button");

// Função para calcular o hash SHA-256
const calculateHash = async (file) => {
    const buffer = await file.arrayBuffer();
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
};

// Atualiza as informações do arquivo selecionado
fileUpload.addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (file) {
        // Exibe as informações do arquivo
        fileName.textContent = file.name;
        fileSize.textContent = `${(file.size / 1024).toFixed(2)} KB`;
        fileHash.textContent = await calculateHash(file);
        fileInfo.style.display = "block";

        // Habilita o botão "Próximo" se a chave pública e o arquivo estiverem selecionados
        if (publicKeyUpload.files.length > 0) {
            nextButton.disabled = false;
        }
    }
});

// Habilita o botão "Próximo" ao selecionar uma chave pública
publicKeyUpload.addEventListener("change", () => {
    if (fileUpload.files.length > 0) {
        nextButton.disabled = false;
    }
});

// Botão Anterior
previousButton.addEventListener("click", () => {
    window.location.href = "/"; // Retorna para a etapa anterior
});

// Botão Próximo
nextButton.addEventListener("click", () => {
    window.location.href = "/etapa3"; // Redireciona para a próxima etapa
});
