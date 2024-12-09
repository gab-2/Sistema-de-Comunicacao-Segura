// Seletores de Elementos
const sendPackageButton = document.getElementById("send-package-button");
const simulationContainer = document.getElementById("simulation-container");
const nextButton = document.getElementById("next-button");
const previousButton = document.getElementById("previous-button");
const statusMessage = document.getElementById("status-message");

// Verifica se o elemento de status existe
if (!statusMessage) {
    console.error("Elemento 'status-message' não encontrado no HTML.");
}

// Função para atualizar a mensagem de status
function updateStatusMessage(color, message) {
    if (statusMessage) {
        statusMessage.innerHTML = `<p style="color: ${color};">${message}</p>`;
    }
}

// Botão "Enviar Pacote"
sendPackageButton.addEventListener("click", async () => {
    sendPackageButton.disabled = true; // Desativa o botão para evitar múltiplos cliques

    try {
        // Atualiza a mensagem de status
        updateStatusMessage("blue", "Enviando pacote...");

        // Simula envio ao servidor
        const formData = new FormData();

        console.log("Iniciando fetch dos arquivos necessários...");

        // Fetch dos arquivos necessários
        const encryptedFile = await fetch("/download/encrypted_file").then(res => {
            if (!res.ok) {
                console.error("Erro ao buscar o arquivo cifrado:", res.status, res.statusText);
                throw new Error("Arquivo cifrado não encontrado.");
            }
            return res.blob();
        });

        const signatureFile = await fetch("/download/signed_file").then(res => {
            if (!res.ok) {
                console.error("Erro ao buscar o arquivo assinado:", res.status, res.statusText);
                throw new Error("Arquivo assinado não encontrado.");
            }
            return res.blob();
        });

        const protectedKeyFile = await fetch("/download/protected_aes_key.pem").then(res => {
            if (!res.ok) {
                console.error("Erro ao buscar a chave AES protegida:", res.status, res.statusText);
                throw new Error("Chave AES protegida não encontrada.");
            }
            return res.blob();
        });

        console.log("Arquivos baixados com sucesso.");

        // Adiciona os arquivos ao FormData com nomes definidos
        formData.append("encrypted_file", encryptedFile, "encrypted_file_name");
        formData.append("signature_file", signatureFile, "signed_file_name");
        formData.append("protected_aes_key", protectedKeyFile, "protected_aes_key.pem");

        console.log("Enviando os arquivos para o servidor...");

        // Faz a requisição ao servidor
        const response = await fetch("/send_package", {
            method: "POST",
            body: formData,
        });

        const result = await response.json();

        if (response.ok) {
            // Atualiza a mensagem de sucesso
            updateStatusMessage("green", "Pacote enviado com sucesso!");
            console.log("Resposta do servidor:", result);
            nextButton.disabled = false; // Habilita o botão "Próximo"
        } else {
            console.error("Erro do servidor ao enviar o pacote:", result.error);
            throw new Error(result.error || "Erro desconhecido ao enviar o pacote.");
        }
    } catch (error) {
        console.error("Erro durante o envio do pacote:", error.message);
        updateStatusMessage("red", `Erro: ${error.message}`);
    } finally {
        sendPackageButton.disabled = false;
    }
});

// Botão Anterior
previousButton.addEventListener("click", () => {
    window.location.href = "/etapa4";
});

// Botão Próximo
nextButton.addEventListener("click", () => {
    window.location.href = "/etapa6";
});
