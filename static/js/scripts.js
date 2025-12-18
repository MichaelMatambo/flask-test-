// --- API Configuration ---
const API_URL = 'http://127.0.0.1:5000/api'; 

// --- 1. CATEGORY DATA STRUCTURE (Refined List) ---
const businessCategories = {
    "🛒 Groceries & Food Retail": [
        "Grocery", "Supermarket", "Grocery Shop", "Wholesaler", 
        "Butchery", "Tuckshop"
    ],
    "🍽️ Food & Dining": [
        "Canteen", "Restaurant", "Quick Food Restaurant", 
        "Candy/Cakes/Spices"
    ],
    "🛠️ Hardware & Tools": [
        "General Hardware", "Agric Hardware", "Auto Hardware"
    ],
    "🏠 Home & Appliances": [
        "Electronics", "Furniture and Home", "Kitchen/Plastics", 
        "Fitment"
    ],
    "👗 Clothing & Fashion": [
        "Clothing and accessories", "Tailor/Fashion", 
        "Jewerlery/Perfume", "Boutique", "Runner" 
    ],
    "⚕️ Medical & Health": [
        "Pharmacy", "Clinic", "Hospital", "Dentist", "Surgery"
    ],
    "📚 Education & Learning": [
        "ECD", "Primary", "Secondary", "Tertiary"
    ],
    "🛎️ Professional Services": [
        "Lodge", "Hotel", "Bank", "Insurance", "Gymn and Fitness", 
        "Driving School"
    ],
    "🎉 Entertainment & Leisure": [
        "Bar, Bottle Store, Night Clubs", "Liquor Store", "Sports Bet"
    ],
    "🚗 Automotive & Fuel": [
        "Fuel Station", "Car Sale"
    ],
    "💅 Health & Beauty": [
        "Barber/Salon", "Beauty and Cosmetics" 
    ],
    "✨ Miscellaneous Retail": [
        "Church", "Gift and Toys", "Printing and Stationary", "LP Gas", "Telecoms" 
    ]
};

// --- 2. DYNAMIC DROPDOWN & GRID POPULATION ---

// IMPORTANT: Replace these paths with the actual relative paths to your images inside the static/images folder
const heroImages = [
    '/static/images/hero-food.png', 
    '/static/images/hero-city.png', 
    '/static/images/hero-tech.png', 
    '/static/images/hero-shop.png'  
];

let currentImageIndex = 0;

function cycleHeroImage() {
    const placeholder = document.getElementById('background-image-placeholder');
    currentImageIndex = (currentImageIndex + 1) % heroImages.length;
    const nextImage = heroImages[currentImageIndex];
    
    // Set the new background image URL
    placeholder.style.backgroundImage = `url('${nextImage}')`;
}

function populateCategories() {
    const select = document.getElementById('primary-category');
    const grid = document.getElementById('categoryGrid');
    
    select.innerHTML = '<option value="">Select Category...</option>';
    grid.innerHTML = '';

    for (const primary in businessCategories) {
        // Populate Dropdown
        const option = document.createElement('option');
        option.value = primary;
        option.textContent = primary;
        select.appendChild(option);

        // Populate Grid Card
        const card = document.createElement('div');
        card.className = 'category-card';
        card.onclick = () => { performCategorySearch(primary); };
        
        const secondaryList = businessCategories[primary].slice(0, 3);
        
        let content = `<h3>${primary}</h3>`;
        secondaryList.forEach(sub => {
            content += `<p>• ${sub}</p>`;
        });
        card.innerHTML = content;
        grid.appendChild(card);
    }
}

// --- 3. SEARCH AND NAVIGATION HANDLERS ---

function performCategorySearch(primaryCategory) {
    const searchTerm = document.getElementById('search-term').value;
    const cityFilter = document.getElementById('city-filter').value;
    
    const params = new URLSearchParams();
    if (searchTerm) params.append('search', searchTerm);
    if (cityFilter) params.append('city', cityFilter);
    
    let categoryToSearch = primaryCategory || document.getElementById('primary-category').value;

    if (categoryToSearch) {
        params.append('category', categoryToSearch);
    }

    window.location.href = `business.html?${params.toString()}`;
}


document.getElementById('searchForm').addEventListener('submit', function(event) {
    event.preventDefault();
    performCategorySearch();
});


// --- 4. MODAL AND AUTH LOGIC ---

const authModal = document.getElementById('authModal');
const modalLogin = document.getElementById('modalLogin');
const modalRegister = document.getElementById('modalRegister');
const modalMessage = document.getElementById('modalMessage');

function displayModalMessage(type, text) {
    modalMessage.className = `message ${type}`;
    modalMessage.textContent = text;
    modalMessage.style.display = 'block';
    setTimeout(() => modalMessage.style.display = 'none', 7000); 
}

function openModal(formType) {
    authModal.style.display = 'block';
    modalMessage.style.display = 'none';
    document.getElementById('loginForm').reset();
    document.getElementById('registerForm').reset();
    
    if (formType === 'register') {
        showRegister();
    } else {
        showLogin();
    }
}

function closeModal() {
    authModal.style.display = 'none';
}

function showLogin() {
    modalRegister.style.display = 'none';
    modalLogin.style.display = 'block';
    modalMessage.style.display = 'none';
}

function showRegister() {
    modalLogin.style.display = 'none';
    modalRegister.style.display = 'block';
    modalMessage.style.display = 'none';
}

window.onclick = function(event) {
    if (event.target == authModal) {
        closeModal();
    }
}

// --- Registration Logic (inside modal) ---
document.getElementById('registerForm').addEventListener('submit', async function(event) {
    event.preventDefault();
    
    const username = document.getElementById('modal-reg-username').value;
    const email = document.getElementById('modal-reg-email').value;
    const password = document.getElementById('modal-reg-password').value;

    if (password.length < 8) {
        displayModalMessage('error', 'Password must be at least 8 characters long.');
        return;
    }

    try {
        const response = await fetch(`${API_URL}/users`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, email, password })
        });

        const data = await response.json();

        if (response.ok) {
            displayModalMessage('success', `Registration successful! Welcome, ${data.username}. Please log in.`);
            this.reset(); 
            showLogin(); 
        } else {
            displayModalMessage('error', data.error || 'Registration failed.');
        }
    } catch (error) {
        displayModalMessage('error', 'Network error or server unavailable.');
        console.error('Registration Error:', error);
    }
});


// --- Login Logic (inside modal) ---
document.getElementById('loginForm').addEventListener('submit', async function(event) {
    event.preventDefault();

    const email = document.getElementById('modal-login-email').value;
    const password = document.getElementById('modal-login-password').value;

    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('jwt_token', data.token);
            localStorage.setItem('username', data.username);
            
            displayModalMessage('success', `Login successful! Redirecting...`);
            this.reset();
            
            setTimeout(() => {
                window.location.href = 'business.html';
            }, 1000);

        } else {
            displayModalMessage('error', data.error || 'Invalid email or password.');
        }
    } catch (error) {
        displayModalMessage('error', 'Network error or server unavailable.');
        console.error('Login Error:', error);
    }
});

// --- INITIALIZATION ---
document.addEventListener('DOMContentLoaded', () => {
    populateCategories();
    
    // Start the dynamic image cycling (e.g., every 8 seconds)
    cycleHeroImage(); 
    setInterval(cycleHeroImage, 8000); 
});

// Expose functions to the global scope for onclick attributes in HTML
window.openModal = openModal;
window.closeModal = closeModal;
window.showLogin = showLogin;
window.showRegister = showRegister;
window.performCategorySearch = performCategorySearch;