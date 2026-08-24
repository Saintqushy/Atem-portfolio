document.addEventListener("DOMContentLoaded", () => {

    /* =====================================================
       ELEMENT REFERENCES
    ====================================================== */

    const menuButton = document.getElementById("menuButton");
    const sideMenu = document.getElementById("sideMenu");
    const menuClose = document.getElementById("menuClose");
    const menuOverlay = document.getElementById("menuOverlay");

    const navLinks = document.querySelectorAll(".nav-link");

    const filterButtons = document.querySelectorAll(".filter-button");
    const technologyCards = document.querySelectorAll(".technology-card");



    /* =====================================================
       SIDE MENU FUNCTIONS
    ====================================================== */

    function openMenu() {

        if (!sideMenu || !menuOverlay || !menuButton) {
            return;
        }

        sideMenu.classList.add("active");
        menuOverlay.classList.add("active");

        sideMenu.setAttribute("aria-hidden", "false");
        menuOverlay.setAttribute("aria-hidden", "false");
        menuButton.setAttribute("aria-expanded", "true");

        document.body.style.overflow = "hidden";
    }


    function closeMenu() {

        if (!sideMenu || !menuOverlay || !menuButton) {
            return;
        }

        sideMenu.classList.remove("active");
        menuOverlay.classList.remove("active");

        sideMenu.setAttribute("aria-hidden", "true");
        menuOverlay.setAttribute("aria-hidden", "true");
        menuButton.setAttribute("aria-expanded", "false");

        document.body.style.overflow = "";
    }



    /* =====================================================
       OPEN MENU
    ====================================================== */

    if (menuButton) {

        menuButton.addEventListener("click", () => {

            const isOpen = sideMenu.classList.contains("active");

            if (isOpen) {
                closeMenu();
            } else {
                openMenu();
            }

        });

    }



    /* =====================================================
       CLOSE BUTTON
    ====================================================== */

    if (menuClose) {

        menuClose.addEventListener("click", closeMenu);

    }



    /* =====================================================
       CLOSE WHEN CLICKING OVERLAY
    ====================================================== */

    if (menuOverlay) {

        menuOverlay.addEventListener("click", closeMenu);

    }



    /* =====================================================
       CLOSE WITH ESCAPE KEY
    ====================================================== */

    document.addEventListener("keydown", (event) => {

        if (
            event.key === "Escape" &&
            sideMenu &&
            sideMenu.classList.contains("active")
        ) {

            closeMenu();

        }

    });



    /* =====================================================
       CLOSE MENU AFTER CLICKING NAV LINK
    ====================================================== */

    navLinks.forEach((link) => {

        link.addEventListener("click", () => {

            closeMenu();

        });

    });



    /* =====================================================
       TECHNOLOGY FILTERING
    ====================================================== */

    filterButtons.forEach((button) => {

        button.addEventListener("click", () => {

            const selectedFilter = button.dataset.filter;

            filterButtons.forEach((btn) => {
                btn.classList.remove("active");
            });

            button.classList.add("active");


            technologyCards.forEach((card) => {

                const categories = card.dataset.category
                    ? card.dataset.category.split(" ")
                    : [];

                if (
                    selectedFilter === "all" ||
                    categories.includes(selectedFilter)
                ) {

                    card.classList.remove("hidden");

                } else {

                    card.classList.add("hidden");

                }

            });

        });

    });



    /* =====================================================
       SMOOTH INTERNAL ANCHOR SCROLLING
    ====================================================== */

    const internalLinks = document.querySelectorAll('a[href^="#"]');

    internalLinks.forEach((link) => {

        link.addEventListener("click", (event) => {

            const targetId = link.getAttribute("href");

            if (!targetId || targetId === "#") {
                return;
            }

            const targetElement = document.querySelector(targetId);

            if (!targetElement) {
                return;
            }

            event.preventDefault();

            targetElement.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        });

    });



    /* =====================================================
       BACK TO TOP
    ====================================================== */

    const backToTop = document.querySelector(".back-to-top");

    if (backToTop) {

        backToTop.addEventListener("click", (event) => {

            event.preventDefault();

            window.scrollTo({
                top: 0,
                behavior: "smooth"
            });

        });

    }



    /* =====================================================
       SIMPLE REVEAL ANIMATION
    ====================================================== */

    const revealElements = document.querySelectorAll(
        ".specialty-card, .technology-card, .project-card, .timeline-item"
    );


    if ("IntersectionObserver" in window) {

        revealElements.forEach((element) => {
            element.classList.add("reveal-item");
        });


        const revealObserver = new IntersectionObserver(
            (entries, observer) => {

                entries.forEach((entry) => {

                    if (entry.isIntersecting) {

                        entry.target.classList.add("revealed");

                        observer.unobserve(entry.target);

                    }

                });

            },
            {
                threshold: 0.12
            }
        );


        revealElements.forEach((element) => {
            revealObserver.observe(element);
        });

    }

});