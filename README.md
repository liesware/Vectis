# Migrar de C y C++ a Rust

Esta guia esta pensada para programadores que ya conocen C o C++ y quieren aprender Rust sin perder sus buenos habitos: pensar en memoria, rendimiento, representacion de datos, interfaces claras y errores explicitos.

Rust no es "C++ con otra sintaxis". Es un lenguaje de sistemas que intenta conservar el control de bajo nivel, pero mueve muchas garantias al compilador: seguridad de memoria, ausencia de data races en codigo seguro, manejo explicito de errores y abstracciones de costo cero.

## 1. Cambia el modelo mental

En C y C++ es comun razonar asi:

- Quien reserva memoria.
- Quien libera memoria.
- Quien puede modificar un puntero.
- Si una referencia sigue viva.
- Si hay aliasing peligroso.

En Rust, esas preguntas siguen existiendo, pero el compilador exige que las respondas mediante tres ideas:

- **Ownership**: cada valor tiene un dueno.
- **Borrowing**: puedes prestar una referencia sin transferir la propiedad.
- **Lifetimes**: las referencias no pueden vivir mas que el dato al que apuntan.

La recompensa es fuerte: muchos errores clasicos de C/C++ dejan de compilar.

## 2. Equivalencias rapidas

| C/C++ | Rust |
| --- | --- |
| `int`, `long`, `uint32_t` | `i32`, `i64`, `u32`, etc. |
| `bool` | `bool` |
| `char *` como texto | `String` o `&str` |
| `T *` | `*mut T`, `*const T`, `Box<T>`, `&T` o `&mut T` segun el caso |
| `std::vector<T>` | `Vec<T>` |
| `std::string` | `String` |
| `std::optional<T>` | `Option<T>` |
| excepciones / codigos de error | `Result<T, E>` |
| `enum class` | `enum` |
| `struct` | `struct` |
| RAII | ownership + `Drop` |
| templates | generics + traits |
| interfaces/clases abstractas | traits |
| `const T&` | `&T` |
| `T&` mutable | `&mut T` |
| `unique_ptr<T>` | `Box<T>` o ownership directo |
| `shared_ptr<T>` | `Rc<T>` o `Arc<T>` |
| `mutex` | `Mutex<T>` |
| `atomic<T>` | `Atomic*` |

## 3. Ownership: el reemplazo natural de muchas reglas manuales

En Rust, asignar o pasar un valor puede mover su propiedad:

```rust
let nombre = String::from("Ada");
let otro = nombre;

// println!("{nombre}"); // Error: nombre fue movido.
println!("{otro}");
```

Esto se parece a un `std::move` automatico para tipos que no implementan `Copy`. Para datos pequenos como enteros, booleanos o floats, Rust copia:

```rust
let a = 10;
let b = a;

println!("{a} {b}");
```

Regla practica:

- Si quieres transferir responsabilidad, pasa el valor por ownership.
- Si solo quieres leer, usa `&T`.
- Si quieres modificar sin transferir, usa `&mut T`.

## 4. Borrowing: referencias sin punteros colgantes

Una referencia inmutable permite leer:

```rust
fn longitud(s: &String) -> usize {
    s.len()
}
```

En Rust idiomatico se prefiere `&str` cuando solo necesitas texto:

```rust
fn longitud(s: &str) -> usize {
    s.len()
}
```

Una referencia mutable permite modificar:

```rust
fn agregar_sufijo(s: &mut String) {
    s.push_str(".log");
}

let mut archivo = String::from("salida");
agregar_sufijo(&mut archivo);
```

La regla importante:

- Puedes tener muchas referencias inmutables a la vez.
- O puedes tener una referencia mutable.
- Pero no ambas al mismo tiempo.

Eso evita data races y aliasing mutable peligroso.

## 5. Lifetimes: no son magia, son alcance

Si vienes de C/C++, piensa en lifetimes como una verificacion estatica contra referencias colgantes.

Este codigo no compila, y esta bien que no compile:

```rust
fn referencia_colgante() -> &String {
    let s = String::from("temporal");
    &s
}
```

`s` se destruye al salir de la funcion. Rust no permite devolver una referencia a memoria invalida.

Muchas veces no escribiras lifetimes explicitamente porque el compilador los infiere. Cuando aparecen, suelen indicar que una funcion devuelve una referencia relacionada con una referencia de entrada:

```rust
fn primero<'a>(a: &'a str, _b: &str) -> &'a str {
    a
}
```

## 6. Manejo de errores: `Result` en vez de excepciones o codigos sueltos

Rust usa `Result<T, E>` para operaciones que pueden fallar:

```rust
use std::fs;

fn leer_config(path: &str) -> Result<String, std::io::Error> {
    let contenido = fs::read_to_string(path)?;
    Ok(contenido)
}
```

El operador `?` propaga el error si ocurre. Es parecido a escribir:

```rust
match fs::read_to_string(path) {
    Ok(contenido) => Ok(contenido),
    Err(error) => Err(error),
}
```

Regla practica:

- Usa `Result` para errores recuperables.
- Usa `panic!` para bugs o estados imposibles, no para flujo normal.
- Evita `unwrap()` en codigo de produccion salvo que el fallo sea realmente imposible o ya validado.

## 7. `Option`: reemplazo seguro para valores nulos

Rust no tiene `null` en referencias seguras. Usa `Option<T>`:

```rust
fn buscar_usuario(id: u32) -> Option<String> {
    if id == 1 {
        Some(String::from("Ada"))
    } else {
        None
    }
}

match buscar_usuario(1) {
    Some(nombre) => println!("Usuario: {nombre}"),
    None => println!("No existe"),
}
```

Esto obliga a manejar ambos casos.

## 8. Structs, enums y pattern matching

Los `struct` se parecen a C/C++:

```rust
struct Punto {
    x: f64,
    y: f64,
}

let p = Punto { x: 1.0, y: 2.0 };
```

Los `enum` de Rust son mas poderosos que los de C/C++ porque cada variante puede llevar datos:

```rust
enum Mensaje {
    Salir,
    Mover { x: i32, y: i32 },
    Escribir(String),
}

fn procesar(mensaje: Mensaje) {
    match mensaje {
        Mensaje::Salir => println!("Salir"),
        Mensaje::Mover { x, y } => println!("Mover a {x}, {y}"),
        Mensaje::Escribir(texto) => println!("{texto}"),
    }
}
```

`match` debe cubrir todos los casos, lo cual reduce errores al evolucionar el codigo.

## 9. Traits: interfaces sin herencia obligatoria

Un trait define comportamiento:

```rust
trait Area {
    fn area(&self) -> f64;
}

struct Circulo {
    radio: f64,
}

impl Area for Circulo {
    fn area(&self) -> f64 {
        std::f64::consts::PI * self.radio * self.radio
    }
}
```

Los traits cubren muchos usos de interfaces, clases abstractas, conceptos y sobrecarga generica.

## 10. Generics sin macros peligrosas

Rust permite programacion generica con bounds:

```rust
fn imprimir<T: std::fmt::Display>(valor: T) {
    println!("{valor}");
}
```

Para quien viene de C++, esto se parece a templates con restricciones mas explicitas.

## 11. Memoria: stack, heap y punteros inteligentes

Rust te deja controlar donde viven los datos:

- Valores locales: normalmente en stack.
- `Box<T>`: aloja un valor en heap con un unico dueno.
- `Vec<T>` y `String`: buffers dinamicos en heap.
- `Rc<T>`: conteo de referencias para un solo hilo.
- `Arc<T>`: conteo de referencias atomico para varios hilos.
- `RefCell<T>` / `Mutex<T>`: mutabilidad controlada en tiempo de ejecucion.

Ejemplo con heap:

```rust
let numero = Box::new(42);
println!("{numero}");
```

Ejemplo compartido entre hilos:

```rust
use std::sync::Arc;

let datos = Arc::new(vec![1, 2, 3]);
let copia = Arc::clone(&datos);
```

## 12. Concurrencia: el compilador ayuda

Rust impide compartir datos entre hilos de forma insegura en codigo seguro.

```rust
use std::sync::{Arc, Mutex};
use std::thread;

let contador = Arc::new(Mutex::new(0));
let mut handles = Vec::new();

for _ in 0..4 {
    let contador = Arc::clone(&contador);
    handles.push(thread::spawn(move || {
        let mut valor = contador.lock().unwrap();
        *valor += 1;
    }));
}

for handle in handles {
    handle.join().unwrap();
}

println!("{}", *contador.lock().unwrap());
```

Si un tipo no es seguro para cruzar hilos, Rust normalmente no te deja hacerlo.

## 13. `unsafe`: existe, pero debe ser pequeno y justificado

Rust tiene codigo `unsafe` para operaciones que el compilador no puede verificar:

- Dereferenciar punteros crudos.
- Llamar funciones FFI.
- Acceder a memoria compartida de bajo nivel.
- Implementar ciertas abstracciones fundamentales.

Ejemplo:

```rust
let x = 5;
let p = &x as *const i32;

unsafe {
    println!("{}", *p);
}
```

Reglas practicas:

- Encapsula `unsafe` detras de una API segura.
- Documenta las invariantes.
- Haz que el bloque `unsafe` sea lo mas pequeno posible.
- No uses `unsafe` para callar al compilador cuando el diseno aun no esta claro.

## 14. Interoperabilidad con C y C++

Rust puede llamar C mediante FFI:

```rust
unsafe extern "C" {
    fn abs(input: i32) -> i32;
}

fn main() {
    let valor = unsafe { abs(-3) };
    println!("{valor}");
}
```

Para exponer funciones Rust a C:

```rust
#[unsafe(no_mangle)]
pub extern "C" fn sumar(a: i32, b: i32) -> i32 {
    a + b
}
```

Para C++ suele convenir usar herramientas como:

- `cxx` para puentes Rust/C++ mas ergonomicos.
- `bindgen` para generar bindings desde headers C/C++.
- `cc` para compilar codigo C/C++ dentro de `build.rs`.

## 15. Cargo: el centro del flujo de trabajo

Cargo reemplaza buena parte de Make, CMake, gestores de dependencias y runners de tests:

```sh
cargo new mi_proyecto
cargo build
cargo run
cargo test
cargo fmt
cargo clippy
cargo doc --open
```

Archivos importantes:

- `Cargo.toml`: metadatos, dependencias y configuracion.
- `Cargo.lock`: versiones exactas resueltas.
- `src/main.rs`: binario principal.
- `src/lib.rs`: biblioteca principal.
- `tests/`: tests de integracion.

## 16. Patrones de migracion desde C/C++

### Empieza por modulos pequenos

No migres todo de golpe. Elige una pieza con limites claros:

- Parser.
- Validacion.
- Algoritmo puro.
- Utilidad de serializacion.
- Biblioteca sin mucha dependencia global.

### Mantén las fronteras simples

Cuando mezcles Rust con C/C++, usa tipos FFI estables:

- Enteros de tamano fijo.
- Punteros opacos.
- Buffers con puntero + longitud.
- Codigos de error explicitos.

Evita cruzar la frontera FFI con tipos Rust complejos como `String`, `Vec<T>` o enums con datos internos.

### Traduce ownership antes que sintaxis

Antes de portar una funcion, responde:

- Quien posee este dato.
- Quien solo lo observa.
- Quien puede modificarlo.
- Cuanto debe vivir.
- Como se reportan errores.

Si esas respuestas estan claras, el codigo Rust suele salir mucho mas limpio.

## 17. Errores comunes al empezar

### Pelear contra el borrow checker

Si el compilador no permite una referencia mutable, normalmente hay aliasing que debes aclarar. Soluciones comunes:

- Reducir el alcance de una referencia.
- Separar lectura y escritura en pasos distintos.
- Mover datos en vez de referenciarlos.
- Usar indices en estructuras tipo `Vec`.
- Reestructurar el modelo de datos.

### Abusar de `clone()`

`clone()` puede estar bien, pero no debe ser el martillo universal. Pregunta primero si necesitas:

- Ownership real.
- Una referencia `&T`.
- Una referencia mutable `&mut T`.
- Un `Arc<T>`.
- Un cambio de estructura.

### Usar `String` cuando basta `&str`

Si una funcion solo lee texto, acepta `&str`:

```rust
fn normalizar(nombre: &str) -> String {
    nombre.trim().to_lowercase()
}
```

Esto permite pasar tanto `String` como literales.

### Usar `unwrap()` demasiado pronto

Para prototipos esta bien. Para codigo serio, propaga o maneja errores:

```rust
let contenido = std::fs::read_to_string("config.toml")?;
```

## 18. Checklist de aprendizaje

Una ruta razonable:

1. Instala Rust con `rustup`.
2. Aprende `cargo build`, `cargo run`, `cargo test`, `cargo fmt` y `cargo clippy`.
3. Practica ownership con `String`, `Vec<T>` y structs propios.
4. Usa `Option` y `Result` hasta que se vuelvan naturales.
5. Escribe tests unitarios.
6. Aprende traits y generics.
7. Aprende iteradores y closures.
8. Migra una utilidad pequena desde C/C++.
9. Agrega FFI si necesitas convivir con codigo existente.
10. Lee codigo de crates populares para absorber estilo idiomatico.

## 19. Mini ejemplo completo

```rust
#[derive(Debug)]
struct Usuario {
    id: u32,
    nombre: String,
}

fn buscar_usuario(usuarios: &[Usuario], id: u32) -> Option<&Usuario> {
    usuarios.iter().find(|usuario| usuario.id == id)
}

fn main() {
    let usuarios = vec![
        Usuario {
            id: 1,
            nombre: String::from("Ada"),
        },
        Usuario {
            id: 2,
            nombre: String::from("Linus"),
        },
    ];

    match buscar_usuario(&usuarios, 1) {
        Some(usuario) => println!("Encontrado: {}", usuario.nombre),
        None => println!("Usuario no encontrado"),
    }
}
```

Este ejemplo muestra varias ideas juntas:

- `Vec<Usuario>` posee la lista.
- `buscar_usuario` solo toma prestado el slice `&[Usuario]`.
- La funcion devuelve `Option<&Usuario>` porque puede no encontrar nada.
- No hay `null`, punteros colgantes ni liberacion manual.

## 20. Consejos finales

Rust premia disenos donde la propiedad de los datos es clara. Al principio el compilador puede sentirse estricto, pero sus errores suelen apuntar a preguntas reales que en C/C++ tambien existen, solo que muchas veces aparecen mas tarde: en produccion, bajo carga o en una maquina distinta.

La mejor forma de migrar es incremental: empieza por codigo con fronteras claras, escribe tests, mide rendimiento y deja que el modelo de ownership te obligue a documentar en el tipo lo que antes vivia en comentarios, convenciones o memoria del equipo.
