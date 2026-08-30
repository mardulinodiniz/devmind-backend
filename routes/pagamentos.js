const express =
    require('express');


const router =
    express.Router();


const db =
    require('../config/database');


const autenticar =
    require('../middlewares/auth');


/*
|--------------------------------------------------------------------------
| CRIAR PAGAMENTO
|--------------------------------------------------------------------------
*/

router.post(
    '/criar',

    autenticar,

    async function(
        req,
        res
    ) {

        try {

            const usuarioId =
                req.usuario.id;


            const {
                curso_id,
                plano
            } = req.body;


            /*
            --------------------------------------------------------------
            VALIDAÇÃO
            --------------------------------------------------------------
            */

            if (
                !curso_id ||
                !plano
            ) {

                return res.status(400).json({
                    erro:
                        'Curso e plano são obrigatórios.'
                });

            }


            /*
            --------------------------------------------------------------
            DEFINIR VALOR
            --------------------------------------------------------------
            */

            let valor;


            if (
                plano === 'mensal'
            ) {

                valor =
                    2500;

            } else if (
                plano === 'completo'
            ) {

                valor =
                    15000;

            } else {

                return res.status(400).json({
                    erro:
                        'Plano inválido.'
                });

            }


            /*
            --------------------------------------------------------------
            GERAR REFERÊNCIA
            --------------------------------------------------------------
            */

            const referencia =
                `DM-${Date.now()}-${usuarioId}`;


            /*
            --------------------------------------------------------------
            CRIAR PAGAMENTO
            --------------------------------------------------------------
            */

            const [resultado] =
                await db.execute(

                    `
                    INSERT INTO pagamentos
                    (
                        usuario_id,
                        curso_id,
                        plano,
                        valor,
                        status,
                        referencia
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    `,

                    [
                        usuarioId,
                        curso_id,
                        plano,
                        valor,
                        'pendente',
                        referencia
                    ]

                );


            /*
            --------------------------------------------------------------
            RESPOSTA
            --------------------------------------------------------------
            */

            res.status(201).json({

                mensagem:
                    'Pedido de pagamento criado com sucesso.',

                pagamento: {

                    id:
                        resultado.insertId,

                    curso_id,

                    plano,

                    valor,

                    status:
                        'pendente',

                    referencia

                }

            });


        } catch (erro) {

            console.error(
                'Erro ao criar pagamento:',
                erro
            );


            res.status(500).json({

                erro:
                    'Erro interno ao criar pagamento.'

            });

        }

    }
);


/*
|--------------------------------------------------------------------------
| MEUS PAGAMENTOS
|--------------------------------------------------------------------------
*/

router.get(
    '/meus',

    autenticar,

    async function(
        req,
        res
    ) {

        try {

            const usuarioId =
                req.usuario.id;


            const [pagamentos] =
                await db.execute(

                    `
                    SELECT
                        p.*,

                        c.titulo
                            AS curso_titulo

                    FROM pagamentos p

                    INNER JOIN cursos c

                        ON c.id =
                        p.curso_id

                    WHERE
                        p.usuario_id = ?

                    ORDER BY
                        p.criado_em DESC
                    `,

                    [
                        usuarioId
                    ]

                );


            res.json(
                pagamentos
            );


        } catch (erro) {

            console.error(
                'Erro ao buscar pagamentos:',
                erro
            );


            res.status(500).json({

                erro:
                    'Erro ao buscar pagamentos.'

            });

        }

    }
);


module.exports =
    router;