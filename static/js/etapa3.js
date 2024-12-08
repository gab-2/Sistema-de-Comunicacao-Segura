// Seletores de Elementos
const previousButton = document.getElementById("previous-button");
const nextButton = document.getElementById("next-button");
const startProcessButton = document.getElementById("start-process");
const processResults = document.getElementById("process-results");
const successMessage = document.getElementById("success-message");
const animationContainer = document.getElementById("animation-container");
const downloadLink = document.createElement("a"); // Link de download

// Configurações iniciais do link de download
downloadLink.classList.add("btn", "download");
downloadLink.style.display = "none";
downloadLink.innerHTML = `<i class="fas fa-download"></i> Baixar Arquivo Cifrado`;
successMessage.appendChild(downloadLink);

// Função para obter informações do arquivo da etapa 2
const getStoredFileInfo = () => {
    const fileData = localStorage.getItem("uploadedFile"); // Certifique-se de usar a mesma chave da etapa 2
    if (!fileData) {
        alert("As informações do arquivo não foram encontradas. Por favor, retorne à etapa 2.");
        window.location.href = "/etapa2";
        return null;
    }
    return JSON.parse(fileData); // Converte os dados armazenados em objeto
};

// Exibe as informações do arquivo carregado da etapa 2
const displayFileInfo = () => {
    const fileInfoContainer = document.getElementById("file-info-container");
    const fileInfo = getStoredFileInfo();

    if (fileInfo) {
        fileInfoContainer.innerHTML = `
            <p><strong>Nome do Arquivo:</strong> ${fileInfo.name}</p>
            <p><strong>Tamanho:</strong> ${(fileInfo.size / 1024).toFixed(2)} KB</p>
            <p><strong>Hash SHA-256:</strong> ${fileInfo.hash}</p>
        `;
        fileInfoContainer.style.display = "block";
    }
};
startProcessButton.addEventListener("click", async () => {
    // Exibir a animação do processo
    startProcessButton.disabled = true;
    animationContainer.style.display = "block";

    // Obtenha o nome do arquivo da etapa 2
    const fileInfo = JSON.parse(localStorage.getItem("uploadedFile"));
    if (!fileInfo) {
        alert("As informações do arquivo não foram encontradas. Por favor, retorne à etapa 2.");
        startProcessButton.disabled = false;
        animationContainer.style.display = "none";
        return;
    }

    try {
        // Envia o nome do arquivo para o backend
        const backendResponse = await fetch("/sign_and_encrypt", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify({ name: fileInfo.name }),
        });

        const result = await backendResponse.json();

        if (backendResponse.ok) {
            // Exibe resultados e link de download
            animationContainer.style.display = "none";
            processResults.style.display = "flex";
            successMessage.style.display = "block";
            downloadLink.href = result.encrypted_file;
            downloadLink.style.display = "inline-block";
            nextButton.disabled = false;
        } else {
            throw new Error(result.error || "Erro durante o processamento.");
        }
    } catch (error) {
        alert(error.message);
        startProcessButton.disabled = false;
        animationContainer.style.display = "none";
    }
});


// Botão Anterior
previousButton.addEventListener("click", () => {
    window.location.href = "/etapa2"; // Redireciona para a etapa anterior
});

// Botão Próximo
nextButton.addEventListener("click", () => {
    window.location.href = "/etapa4"; // Redireciona para a próxima etapa
});

// Inicializa a página exibindo as informações do arquivo
displayFileInfo();
