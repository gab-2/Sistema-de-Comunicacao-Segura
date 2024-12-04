// Variáveis para controlar estados
let rsaGenerated = false;
let aesGenerated = false;
let currentStep = 1; // Etapa inicial

// Função para verificar se o botão Próximo pode ser habilitado
const checkNextButton = () => {
    const nextButton = document.getElementById("next-button");
    if (rsaGenerated && aesGenerated) {
        nextButton.disabled = false;
        nextButton.style.cursor = "pointer";
    }
};

// Função para mostrar ou esconder o loader
const showLoader = (show) => {
    console.log(show ? "Mostrando loader" : "Escondendo loader");
    const loader = document.getElementById("loader");
    if (loader) loader.style.display = show ? "block" : "none";
};

// Função para manipular exibição de chaves geradas
const handleKeys = (data, keyType) => {
    if (keyType === "private_key") {
        rsaGenerated = true;

        // Exibir mensagem de sucesso e saída de chaves RSA
        document.getElementById("rsa-success").style.display = "flex";
        document.getElementById("rsa-output").style.display = "block";

        // Preencher os inputs
        document.getElementById("public-key").value = data.public_key;
        document.getElementById("private-key").value = data.private_key;

        // Configurar os botões de download
        document.getElementById("download-public").onclick = () => {
            window.location.href = data.public_key_file;
        };
        document.getElementById("download-private").onclick = () => {
            window.location.href = data.private_key_file;
        };
    } else if (keyType === "aes_key") {
        aesGenerated = true;

        // Exibir mensagem de sucesso e saída da chave AES
        document.getElementById("aes-success").style.display = "flex";
        document.getElementById("aes-output").style.display = "block";

        // Preencher o input
        document.getElementById("aes-key").value = data.aes_key;

        // Configurar o botão de download
        document.getElementById("download-aes").onclick = () => {
            window.location.href = data.aes_key_file;
        };
    }

    // Verificar botão Próximo
    checkNextButton();
};

// Função para gerar chaves (fetch)
const generateKeys = (url, keyType) => {
    showLoader(true);

    fetch(url, { method: "POST" })
        .then(response => response.json())
        .then(data => {
            showLoader(false);
            handleKeys(data, keyType);
        })
        .catch(err => {
            showLoader(false);
            console.error("Erro ao gerar chaves:", err);
        });
};

// Atualiza a sidebar conforme o progresso
const updateSidebar = () => {
    const steps = document.querySelectorAll("#sidebar-steps li");
    steps.forEach((step) => {
        const stepNumber = parseInt(step.dataset.step, 10);
        if (stepNumber < currentStep) {
            // Marca etapas concluídas
            step.classList.remove("active");
            step.classList.add("completed");
        } else if (stepNumber === currentStep) {
            // Marca a etapa ativa
            step.classList.add("active");
            step.classList.remove("completed");
        } else {
            // Remove as marcações das etapas futuras
            step.classList.remove("active");
            step.classList.remove("completed");
        }
    });
};

// Evento para o botão "Próximo"
document.getElementById("next-button").addEventListener("click", () => {
    const totalSteps = document.querySelectorAll("#sidebar-steps li").length;
    if (currentStep < totalSteps) {
        currentStep++;
        updateSidebar();
    }

    // Redirecionar para outra etapa, se necessário
    if (currentStep === 2) {
        window.location.href = "/etapa2"; // Ajuste conforme suas rotas
    }
});

// Eventos dos botões
document.getElementById("generate-rsa").addEventListener("click", () => {
    generateKeys("/generate_rsa", "private_key");
});

document.getElementById("generate-aes").addEventListener("click", () => {
    generateKeys("/generate_aes", "aes_key");
});

document.getElementById("next-button").addEventListener("click", () => {
    window.location.href = "/etapa2";
});
