// Seletores de Elementos
const sendPackageButton = document.getElementById("send-package-button");
const statusMessage = document.getElementById("status-message");
const downloadLinks = document.getElementById("download-links");
const downloadZipLink = document.getElementById("download-zip");
const nextButton = document.getElementById("next-button");
const previousButton = document.getElementById("previous-button");

// Função para atualizar a mensagem de status
function updateStatusMessage(color, message) {
    if (statusMessage) {
        statusMessage.innerHTML = `<p style="color: ${color};">${message}</p>`;
    }
}

// Função para exibir o link de download do pacote ZIP
function showDownloadLink(zipUrl) {
    if (downloadLinks && downloadZipLink) {
        downloadZipLink.href = zipUrl; // Atualiza o link do ZIP
        downloadLinks.style.display = "block"; // Exibe o link de download
    } else {
        console.error("Elementos de download não encontrados no HTML.");
    }
}

// Evento de clique no botão "Enviar Pacote"
sendPackageButton.addEventListener("click", async () => {
    sendPackageButton.disabled = true;

    try {
        updateStatusMessage("blue", "Enviando pacote...");

        const formData = new FormData();

        // Simula envio de arquivos (fetch para arquivos locais no servidor)
        const encryptedFile = await fetch("/download/encrypted_file").then(res => res.blob());
        const signatureFile = await fetch("/download/signed_file").then(res => res.blob());
        const protectedKeyFile = await fetch("/download/protected_aes_key.pem").then(res => res.blob());

        // Adiciona arquivos ao FormData
        formData.append("encrypted_file", new File([encryptedFile], "encrypted_file_name"));
        formData.append("signature_file", new File([signatureFile], "signed_file_name"));
        formData.append("protected_aes_key", new File([protectedKeyFile], "protected_aes_key.pem"));

        // Faz a requisição ao backend para criar o ZIP
        const response = await fetch("/send_package", {
            method: "POST",
            body: formData,
        });

        const result = await response.json();

        if (response.ok) {
            updateStatusMessage("green", "Pacote enviado com sucesso!");

            // Mostra o link para baixar o arquivo ZIP
            showDownloadLink("/download/package_zip");

            nextButton.disabled = false; // Habilita o botão "Próximo"
        } else {
            throw new Error(result.error || "Erro desconhecido ao enviar o pacote.");
        }
    } catch (error) {
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
