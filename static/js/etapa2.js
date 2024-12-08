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
// Atualiza as informações do arquivo selecionado e envia para o backend
fileUpload.addEventListener("change", async (event) => {
    const file = event.target.files[0];
    if (file) {
        // Calcula o hash e exibe as informações
        const hash = await calculateHash(file);
        fileName.textContent = file.name;
        fileSize.textContent = `${(file.size / 1024).toFixed(2)} KB`;
        fileHash.textContent = hash;
        fileInfo.style.display = "block";

        // Salva as informações do arquivo no localStorage
        const fileData = {
            name: file.name,
            size: file.size,
            hash: hash,
        };
        localStorage.setItem("uploadedFile", JSON.stringify(fileData));

        // Envia o arquivo para o backend
        const formData = new FormData();
        formData.append("file", file);

        try {
            const response = await fetch("/upload_file", {
                method: "POST",
                body: formData,
            });

            const result = await response.json();

            if (response.ok) {
                console.log("Arquivo enviado para o backend:", result);
            } else {
                alert(result.error || "Erro ao enviar o arquivo para o backend.");
            }
        } catch (error) {
            console.error("Erro ao enviar o arquivo:", error);
            alert("Erro ao enviar o arquivo para o backend.");
        }

        // Habilita o botão "Próximo" se a chave pública também foi selecionada
        if (publicKeyUpload.files.length > 0) {
            nextButton.disabled = false;
        }
    }
});


// Armazena a chave pública no sessionStorage
publicKeyUpload.addEventListener("change", () => {
    const publicKeyFile = publicKeyUpload.files[0];
    if (publicKeyFile) {
        sessionStorage.setItem("uploadedPublicKeyName", publicKeyFile.name);

        // Log para depuração
        console.log("Chave pública armazenada:", publicKeyFile.name);

        // Habilita o botão "Próximo" se o arquivo já estiver selecionado
        if (fileUpload.files.length > 0) {
            nextButton.disabled = false;
        }
    }
});

// Botão Anterior
previousButton.addEventListener("click", () => {
    window.location.href = "/"; // Retorna para a etapa anterior
});

// Botão Próximo
nextButton.addEventListener("click", () => {
    // Verifica se as informações estão armazenadas antes de prosseguir
    const fileInfo = localStorage.getItem("uploadedFile"); // Chave correta
    const publicKeyName = sessionStorage.getItem("uploadedPublicKeyName");

    if (!fileInfo || !publicKeyName) {
        alert("Por favor, certifique-se de que o arquivo e a chave pública foram carregados corretamente.");
        return;
    }

    // Redireciona para a próxima etapa
    window.location.href = "/etapa3";
});
