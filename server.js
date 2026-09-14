const express = require('express');
const db = require('./db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const axios = require('axios');

const autenticar = require('./middleware/authMiddleware');
const apenasAdmin = require('./middleware/admin');

const JWT_SECRET = 'minha_chave_secreta_plataforma';

const BITPAY_API_URL = 'https://api-sandbox.bitpay.ao/v1';
const BITPAY_SECRET_KEY = process.env.BITPAY_SECRET_KEY;

const app = express();

app.use(cors());

app.use(express.json());

const PORT = process.env.PORT || 3000;

// Rota inicial
app.get('/', (req, res) => {
    res.json({
        mensagem: 'API da Plataforma de Estruturas de Dados funcionando!'
    });
});

// Buscar todos os cursos
app.get('/api/cursos', (req, res) => {
    const sql = 'SELECT * FROM cursos ORDER BY id';

    db.query(sql, (err, resultados) => {
        if (err) {
            console.error('Erro ao buscar cursos:', err);
            return res.status(500).json({
                erro: 'Erro ao buscar cursos'
            });
        }

        res.json(resultados);
    });
});

app.get('/api/cursos/:cursoId/modulos', (req, res) => {
    const { cursoId } = req.params;
    const cabecalho = req.headers.authorization;

    let usuarioId = null;

    // Se houver token, identifica o usuário
    if (cabecalho) {
        const partes = cabecalho.split(' ');

        if (partes.length === 2 && partes[0] === 'Bearer') {
            try {
                const usuario = jwt.verify(partes[1], JWT_SECRET);
                usuarioId = usuario.id;
            } catch (error) {
                usuarioId = null;
            }
        }
    }

    const sqlModulos = `
        SELECT id, titulo, descricao, ordem, gratuito
        FROM modulos
        WHERE curso_id = ?
        ORDER BY ordem
    `;

    db.query(sqlModulos, [cursoId], (err, modulos) => {
        if (err) {
            console.error('Erro ao buscar módulos:', err);

            return res.status(500).json({
                erro: 'Erro ao buscar módulos'
            });
        }

        // Usuário não autenticado:
        // apenas módulos gratuitos ficam disponíveis
        if (!usuarioId) {
            const resultado = modulos.map(modulo => ({
                ...modulo,
                bloqueado: modulo.gratuito !== 1
            }));

            return res.json(resultado);
        }

        // Usuário autenticado: buscar o limite de acesso
        const sqlAcesso = `
            SELECT modulo_maximo, status
            FROM acessos_cursos
            WHERE usuario_id = ?
            AND curso_id = ?
            LIMIT 1
        `;

        db.query(sqlAcesso, [usuarioId, cursoId], (erroAcesso, acessos) => {
            if (erroAcesso) {
                console.error('Erro ao verificar acesso:', erroAcesso);

                return res.status(500).json({
                    erro: 'Erro ao verificar acesso'
                });
            }

            let moduloMaximo = 2;

            if (
                acessos.length > 0 &&
                acessos[0].status === 'ativo'
            ) {
                moduloMaximo = acessos[0].modulo_maximo;
            }

            const resultado = modulos.map(modulo => ({
                ...modulo,
                bloqueado: modulo.ordem > moduloMaximo
            }));

            res.json(resultado);
        });
    });
});

app.get('/api/modulos/:moduloId/aulas', (req, res) => {
    const { moduloId } = req.params;

    // Primeiro buscamos o módulo para saber a sua ordem
    const sqlModulo = `
        SELECT id, curso_id, ordem, gratuito
        FROM modulos
        WHERE id = ?
        LIMIT 1
    `;

    db.query(sqlModulo, [moduloId], (erroModulo, modulos) => {
        if (erroModulo) {
            console.error('Erro ao buscar módulo:', erroModulo);

            return res.status(500).json({
                erro: 'Erro ao verificar módulo'
            });
        }

        if (modulos.length === 0) {
            return res.status(404).json({
                erro: 'Módulo não encontrado'
            });
        }

        const modulo = modulos[0];

        // Módulos gratuitos: acesso livre
        if (modulo.gratuito === 1) {
            return buscarAulas();
        }

        // Módulo pago: precisa de token
        const cabecalho = req.headers.authorization;

        if (!cabecalho) {
            return res.status(401).json({
                erro: 'Você precisa estar autenticado para acessar este conteúdo'
            });
        }

        const partes = cabecalho.split(' ');

        if (partes.length !== 2 || partes[0] !== 'Bearer') {
            return res.status(401).json({
                erro: 'Formato do token inválido'
            });
        }

        const token = partes[1];

        let usuario;

        try {
            usuario = jwt.verify(token, JWT_SECRET);
        } catch (error) {
            return res.status(401).json({
                erro: 'Token inválido ou expirado'
            });
        }

        // Verificar até qual módulo o usuário tem acesso
        const sqlAcesso = `
            SELECT modulo_maximo, status
            FROM acessos_cursos
            WHERE usuario_id = ?
            AND curso_id = ?
            LIMIT 1
        `;

        db.query(
            sqlAcesso,
            [usuario.id, modulo.curso_id],
            (erroAcesso, acessos) => {
                if (erroAcesso) {
                    console.error('Erro ao verificar acesso:', erroAcesso);

                    return res.status(500).json({
                        erro: 'Erro ao verificar acesso do usuário'
                    });
                }

                if (
                    acessos.length === 0 ||
                    acessos[0].status !== 'ativo'
                ) {
                    return res.status(403).json({
                        erro: 'Você não possui acesso a este curso'
                    });
                }

                const moduloMaximo = acessos[0].modulo_maximo;

                if (modulo.ordem > moduloMaximo) {
                    return res.status(403).json({
                        erro: 'Você ainda não possui acesso a este módulo',
                        modulo_maximo: moduloMaximo
                    });
                }

                buscarAulas();
            }
        );

        // Função que busca as aulas somente após autorização
        function buscarAulas() {
            const sqlAulas = `
                SELECT id, modulo_id, titulo, descricao,
                       video_url, ordem, gratuita, ativa
                FROM aulas
                WHERE modulo_id = ?
                AND ativa = 1
                ORDER BY ordem
            `;

            db.query(sqlAulas, [moduloId], (err, resultados) => {
                if (err) {
                    console.error('Erro ao buscar aulas:', err);

                    return res.status(500).json({
                        erro: 'Erro ao buscar aulas'
                    });
                }

                res.json(resultados);
            });
        }
    });
});

app.post('/api/auth/register', async (req, res) => {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
        return res.status(400).json({
            erro: 'Nome, email e senha são obrigatórios'
        });
    }

    try {
        const senhaHash = await bcrypt.hash(senha, 10);

        const sql = `
            INSERT INTO usuarios (nome, email, senha)
            VALUES (?, ?, ?)
        `;

        db.query(sql, [nome, email, senhaHash], (err, resultado) => {
            if (err) {
                if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({
                        erro: 'Este email já está cadastrado'
                    });
                }

                console.error('Erro ao cadastrar usuário:', err);

                return res.status(500).json({
                    erro: 'Erro ao cadastrar usuário'
                });
            }

            const usuarioId = resultado.insertId;

            const sqlAcesso = `
                INSERT INTO acessos_cursos
                (usuario_id, curso_id, modulo_maximo, status)
                VALUES (?, 1, 2, 'ativo')
            `;

            db.query(sqlAcesso, [usuarioId], (erroAcesso) => {
                if (erroAcesso) {
                    console.error('Erro ao criar acesso:', erroAcesso);

                    return res.status(500).json({
                        erro: 'Usuário criado, mas houve um erro ao criar o acesso ao curso'
                    });
                }

                res.status(201).json({
                    mensagem: 'Usuário cadastrado com sucesso!',
                    usuario: {
                        id: usuarioId,
                        nome,
                        email,
                        tipo: 'aluno'
                    },
                    acesso: {
                        curso_id: 1,
                        modulo_maximo: 2
                    }
                });
            });
        });

    } catch (error) {
        console.error('Erro no bcrypt:', error);

        res.status(500).json({
            erro: 'Erro ao processar senha'
        });
    }
});

app.post('/api/auth/login', (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({
            erro: 'Email e senha são obrigatórios'
        });
    }

    const sql = 'SELECT * FROM usuarios WHERE email = ?';

    db.query(sql, [email], async (err, resultados) => {
        if (err) {
            console.error('Erro ao buscar usuário:', err);

            return res.status(500).json({
                erro: 'Erro interno do servidor'
            });
        }

        if (resultados.length === 0) {
            return res.status(401).json({
                erro: 'Email ou senha incorretos'
            });
        }

        const usuario = resultados[0];

        const senhaCorreta = await bcrypt.compare(
            senha,
            usuario.senha
        );

        if (!senhaCorreta) {
            return res.status(401).json({
                erro: 'Email ou senha incorretos'
            });
        }

        const token = jwt.sign(
            {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                tipo: usuario.tipo
            },
            JWT_SECRET,
            {
                expiresIn: '7d'
            }
        );

        res.json({
            mensagem: 'Login realizado com sucesso!',
            token: token,
            usuario: {
                id: usuario.id,
                nome: usuario.nome,
                email: usuario.email,
                tipo: usuario.tipo
            }
        });
    });
});

app.get('/api/perfil', autenticar, (req, res) => {
    res.json({
        mensagem: 'Você está autenticado!',
        usuario: req.usuario
    });
});

app.get('/api/admin/teste', autenticar, apenasAdmin, (req, res) => {
    res.json({
        mensagem: 'Área administrativa acessada com sucesso!',
        administrador: req.usuario
    });
});

app.put('/api/admin/acessos/:usuarioId', autenticar, apenasAdmin, (req, res) => {
    const { usuarioId } = req.params;
    const { modulo_maximo } = req.body;

    if (!modulo_maximo || ![2, 9, 15].includes(Number(modulo_maximo))) {
        return res.status(400).json({
            erro: 'modulo_maximo deve ser 2, 9 ou 15'
        });
    }

    const sql = `
        UPDATE acessos_cursos
        SET modulo_maximo = ?,
            status = 'ativo'
        WHERE usuario_id = ?
        AND curso_id = 1
    `;

    db.query(sql, [modulo_maximo, usuarioId], (err, resultado) => {
        if (err) {
            console.error('Erro ao atualizar acesso:', err);

            return res.status(500).json({
                erro: 'Erro ao atualizar acesso'
            });
        }

        if (resultado.affectedRows === 0) {
            return res.status(404).json({
                erro: 'Acesso do usuário não encontrado'
            });
        }

        res.json({
            mensagem: 'Acesso atualizado com sucesso!',
            usuario_id: Number(usuarioId),
            curso_id: 1,
            modulo_maximo: Number(modulo_maximo)
        });
    });
});

app.post('/api/pagamentos/criar', autenticar, async (req, res) => {
    const { curso_id, plano, telefone } = req.body;
    const usuarioId = req.usuario.id;

    if (!curso_id || !plano || !telefone) {
        return res.status(400).json({
            erro: 'curso_id, plano e telefone são obrigatórios'
        });
    }

    let valor;

    if (plano === 'parcial') {
        valor = 5000;
    } else if (plano === 'upgrade') {
        valor = 5000;
    } else if (plano === 'completo') {
        valor = 10000;
    } else {
        return res.status(400).json({
            erro: 'Plano inválido'
        });
    }

    const referencia = `PAG-${Date.now()}-${usuarioId}`;

    try {
        const respostaBitPay = await axios.post(
            `${BITPAY_API_URL}/payment_intents`,
            {
                amount: valor,
                currency: 'AOA',
                payment_method: 'multicaixa_express',
                customer: {
                    mobile: telefone
                },
                merchant_reference: referencia
            },
            {
                headers: {
                    Authorization: `Bearer ${BITPAY_SECRET_KEY}`,
                    'Idempotency-Key': referencia,
                    'Content-Type': 'application/json'
                }
            }
        );

        const pagamentoBitPay = respostaBitPay.data;

        const sql = `
            INSERT INTO pagamentos
            (usuario_id, curso_id, plano, valor, moeda, status, referencia)
            VALUES (?, ?, ?, ?, 'AOA', 'pendente', ?)
        `;

        db.query(
            sql,
            [usuarioId, curso_id, plano, valor, referencia],
            (err, resultado) => {
                if (err) {
                    console.error('Erro ao salvar pagamento:', err);

                    return res.status(500).json({
                        erro: 'Pagamento criado no BitPay, mas não foi possível salvar no banco'
                    });
                }

                res.status(201).json({
                    mensagem: 'Pagamento criado com sucesso!',
                    pagamento: {
                        id: resultado.insertId,
                        curso_id: Number(curso_id),
                        plano,
                        valor,
                        moeda: 'AOA',
                        status: 'pendente',
                        referencia,
                        bitpay: pagamentoBitPay
                    }
                });
            }
        );

    } catch (erro) {
        console.error(
            'Erro BitPay:',
            erro.response?.data || erro.message
        );

        return res.status(500).json({
            erro: 'Não foi possível criar o pagamento no BitPay'
        });
    }
});

app.put(
    '/api/admin/pagamentos/:pagamentoId/confirmar',
    autenticar,
    apenasAdmin,
    (req, res) => {
        const { pagamentoId } = req.params;

        const sqlBuscar = `
            SELECT *
            FROM pagamentos
            WHERE id = ?
            LIMIT 1
        `;

        db.query(sqlBuscar, [pagamentoId], (erro, pagamentos) => {
            if (erro) {
                console.error('Erro ao buscar pagamento:', erro);

                return res.status(500).json({
                    erro: 'Erro ao buscar pagamento'
                });
            }

            if (pagamentos.length === 0) {
                return res.status(404).json({
                    erro: 'Pagamento não encontrado'
                });
            }

            const pagamento = pagamentos[0];

            if (pagamento.status === 'pago') {
                return res.status(400).json({
                    erro: 'Este pagamento já foi confirmado'
                });
            }

            if (pagamento.status === 'cancelado') {
                return res.status(400).json({
                    erro: 'Pagamento cancelado não pode ser confirmado'
                });
            }

            let moduloMaximo;

            if (pagamento.plano === 'parcial') {
                moduloMaximo = 9;
            } else if (
                pagamento.plano === 'upgrade' ||
                pagamento.plano === 'completo'
            ) {
                moduloMaximo = 15;
            } else {
                return res.status(400).json({
                    erro: 'Plano de pagamento inválido'
                });
            }

            const sqlPagamento = `
                UPDATE pagamentos
                SET status = 'pago',
                    data_pagamento = CURRENT_TIMESTAMP
                WHERE id = ?
            `;

            db.query(
                sqlPagamento,
                [pagamentoId],
                (erroPagamento) => {
                    if (erroPagamento) {
                        console.error(
                            'Erro ao confirmar pagamento:',
                            erroPagamento
                        );

                        return res.status(500).json({
                            erro: 'Erro ao confirmar pagamento'
                        });
                    }

                    const sqlAcesso = `
                        UPDATE acessos_cursos
                        SET modulo_maximo = ?,
                            status = 'ativo'
                        WHERE usuario_id = ?
                        AND curso_id = ?
                    `;

                    db.query(
                        sqlAcesso,
                        [
                            moduloMaximo,
                            pagamento.usuario_id,
                            pagamento.curso_id
                        ],
                        (erroAcesso, resultadoAcesso) => {
                            if (erroAcesso) {
                                console.error(
                                    'Erro ao atualizar acesso:',
                                    erroAcesso
                                );

                                return res.status(500).json({
                                    erro: 'Pagamento confirmado, mas houve erro ao liberar acesso'
                                });
                            }

                            if (resultadoAcesso.affectedRows === 0) {
                                return res.status(404).json({
                                    erro: 'Pagamento confirmado, mas acesso do aluno não foi encontrado'
                                });
                            }

                            res.json({
                                mensagem: 'Pagamento confirmado e acesso liberado com sucesso!',
                                pagamento_id: Number(pagamentoId),
                                usuario_id: pagamento.usuario_id,
                                curso_id: pagamento.curso_id,
                                modulo_maximo: moduloMaximo
                            });
                        }
                    );
                }
            );
        });
    }
);

app.get('/api/meu-acesso', autenticar, (req, res) => {
    const usuarioId = req.usuario.id;

    const sql = `
        SELECT
            u.id AS usuario_id,
            u.nome,
            u.email,
            u.tipo,
            ac.curso_id,
            ac.modulo_maximo,
            ac.status
        FROM usuarios u
        LEFT JOIN acessos_cursos ac
            ON ac.usuario_id = u.id
            AND ac.curso_id = 1
        WHERE u.id = ?
        LIMIT 1
    `;

    db.query(sql, [usuarioId], (err, resultados) => {
        if (err) {
            console.error('Erro ao buscar acesso:', err);

            return res.status(500).json({
                erro: 'Erro ao buscar dados do usuário'
            });
        }

        if (resultados.length === 0) {
            return res.status(404).json({
                erro: 'Usuário não encontrado'
            });
        }

        const dados = resultados[0];

        res.json({
            usuario: {
                id: dados.usuario_id,
                nome: dados.nome,
                email: dados.email,
                tipo: dados.tipo
            },
            acesso: {
                curso_id: dados.curso_id,
                modulo_maximo: dados.modulo_maximo || 2,
                status: dados.status || 'ativo'
            }
        });
    });
});

app.put('/api/progresso/:aulaId', autenticar, (req, res) => {
    const usuarioId = req.usuario.id;
    const { aulaId } = req.params;
    const { concluida, ultima_posicao } = req.body;

    if (
        concluida !== undefined &&
        typeof concluida !== 'boolean' &&
        concluida !== 0 &&
        concluida !== 1
    ) {
        return res.status(400).json({
            erro: 'O campo concluida deve ser true, false, 1 ou 0'
        });
    }

    const posicao = Number(ultima_posicao);

    if (
        ultima_posicao !== undefined &&
        (!Number.isFinite(posicao) || posicao < 0)
    ) {
        return res.status(400).json({
            erro: 'ultima_posicao deve ser um número maior ou igual a zero'
        });
    }

    const sqlAula = `
        SELECT
            a.id AS aula_id,
            a.modulo_id,
            a.ativa,
            m.curso_id,
            m.ordem AS modulo_ordem,
            m.gratuito AS modulo_gratuito
        FROM aulas a
        INNER JOIN modulos m ON m.id = a.modulo_id
        WHERE a.id = ?
        LIMIT 1
    `;

    db.query(sqlAula, [aulaId], (erroAula, aulas) => {
        if (erroAula) {
            console.error('Erro ao buscar aula:', erroAula);

            return res.status(500).json({
                erro: 'Erro ao verificar aula'
            });
        }

        if (aulas.length === 0 || aulas[0].ativa !== 1) {
            return res.status(404).json({
                erro: 'Aula não encontrada ou inativa'
            });
        }

        const aula = aulas[0];

        // Se o módulo for gratuito, o aluno já pode guardar o progresso
        if (aula.modulo_gratuito === 1) {
            return salvarProgresso();
        }

        // Para módulos pagos, verificar o acesso do aluno
        const sqlAcesso = `
            SELECT modulo_maximo, status
            FROM acessos_cursos
            WHERE usuario_id = ?
            AND curso_id = ?
            LIMIT 1
        `;

        db.query(
            sqlAcesso,
            [usuarioId, aula.curso_id],
            (erroAcesso, acessos) => {
                if (erroAcesso) {
                    console.error('Erro ao verificar acesso:', erroAcesso);

                    return res.status(500).json({
                        erro: 'Erro ao verificar acesso do aluno'
                    });
                }

                if (
                    acessos.length === 0 ||
                    acessos[0].status !== 'ativo' ||
                    aula.modulo_ordem > acessos[0].modulo_maximo
                ) {
                    return res.status(403).json({
                        erro: 'Você não possui acesso a esta aula'
                    });
                }

                salvarProgresso();
            }
        );

        function salvarProgresso() {
            const concluidaValor =
                concluida === true || concluida === 1 ? 1 : 0;

            const ultimaPosicaoValor =
                ultima_posicao !== undefined ? posicao : 0;

            const sqlProgresso = `
                INSERT INTO progresso_aulas
                    (usuario_id, aula_id, concluida, ultima_posicao, data_conclusao)
                VALUES (?, ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    concluida = VALUES(concluida),
                    ultima_posicao = VALUES(ultima_posicao),
                    data_conclusao = CASE
                        WHEN VALUES(concluida) = 1
                        THEN CURRENT_TIMESTAMP
                        ELSE NULL
                    END
            `;

            const dataConclusao =
                concluidaValor === 1 ? new Date() : null;

            db.query(
                sqlProgresso,
                [
                    usuarioId,
                    aulaId,
                    concluidaValor,
                    ultimaPosicaoValor,
                    dataConclusao
                ],
                (erroProgresso) => {
                    if (erroProgresso) {
                        console.error(
                            'Erro ao salvar progresso:',
                            erroProgresso
                        );

                        return res.status(500).json({
                            erro: 'Erro ao salvar progresso'
                        });
                    }

                    res.json({
                        mensagem: 'Progresso salvo com sucesso!',
                        aula_id: Number(aulaId),
                        concluida: concluidaValor === 1,
                        ultima_posicao: ultimaPosicaoValor
                    });
                }
            );
        }
    });
});

app.get(
    '/api/progresso/:aulaId',
    autenticar,
    (req, res) => {

        const usuarioId =
            req.usuario.id;

        const { aulaId } =
            req.params;


        const sql = `
            SELECT
                aula_id,
                concluida,
                ultima_posicao,
                data_conclusao
            FROM progresso_aulas
            WHERE usuario_id = ?
            AND aula_id = ?
            LIMIT 1
        `;


        db.query(
            sql,
            [usuarioId, aulaId],
            (err, resultados) => {

                if (err) {

                    console.error(
                        'Erro ao buscar progresso:',
                        err
                    );

                    return res.status(500).json({
                        erro:
                            'Erro ao buscar progresso da aula'
                    });
                }


                if (
                    resultados.length === 0
                ) {

                    return res.json({

                        aula_id:
                            Number(aulaId),

                        concluida:
                            false,

                        ultima_posicao:
                            0,

                        data_conclusao:
                            null
                    });
                }


                const progresso =
                    resultados[0];


                res.json({

                    aula_id:
                        progresso.aula_id,

                    concluida:
                        progresso.concluida === 1,

                    ultima_posicao:
                        Number(
                            progresso.ultima_posicao || 0
                        ),

                    data_conclusao:
                        progresso.data_conclusao
                });
            }
        );
    }
);

app.get('/api/cursos/:cursoId/progresso', autenticar, (req, res) => {
    const usuarioId = req.usuario.id;
    const { cursoId } = req.params;

    const sql = `
        SELECT
            COUNT(a.id) AS total_aulas,
            COALESCE(SUM(CASE WHEN p.concluida = 1 THEN 1 ELSE 0 END), 0) AS aulas_concluidas,
            ROUND(
                (
                    COALESCE(
                        SUM(CASE WHEN p.concluida = 1 THEN 1 ELSE 0 END),
                        0
                    ) / NULLIF(COUNT(a.id), 0)
                ) * 100,
                2
            ) AS percentual
        FROM aulas a
        INNER JOIN modulos m
            ON m.id = a.modulo_id
        LEFT JOIN progresso_aulas p
            ON p.aula_id = a.id
            AND p.usuario_id = ?
        WHERE m.curso_id = ?
        AND a.ativa = 1
    `;

    db.query(sql, [usuarioId, cursoId], (err, resultados) => {
        if (err) {
            console.error('Erro ao buscar progresso:', err);

            return res.status(500).json({
                erro: 'Erro ao buscar progresso do curso'
            });
        }

        const progresso = resultados[0];

        res.json({
            curso_id: Number(cursoId),
            total_aulas: Number(progresso.total_aulas),
            aulas_concluidas: Number(progresso.aulas_concluidas),
            percentual: Number(progresso.percentual || 0)
        });
    });
});

app.listen(PORT, () => {
    console.log(`Servidor rodando em http://localhost:${PORT}`);
});